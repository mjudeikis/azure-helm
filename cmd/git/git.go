package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	git "gopkg.in/libgit2/git2go.v27"
)

var (
	reponame = flag.String("reponame", "openshift/openshift-azure", "GitHub repo name, e.g. openshift/openshift-azure")
	repopath = flag.String("repopath", ".", "path to local checked out git repo")
)

type giter struct {
	gh *github.Client
}

func newGiter(ctx context.Context) (*giter, error) {
	var cli *http.Client

	if token, found := os.LookupEnv("GITHUB_TOKEN"); found {
		cli = oauth2.NewClient(
			ctx,
			oauth2.StaticTokenSource(
				&oauth2.Token{AccessToken: token},
			),
		)
	} else {
		return nil, fmt.Errorf("env GITHUB_TOKEN needs to be set with a valid Github Personal Access Token")
	}

	return &giter{
		gh: github.NewClient(cli),
	}, nil
}

// getRef returns the commit branch reference object if it exists or creates it
// from the base branch before returning it.
func (g *giter) getRef(ctx context.Context) (ref *github.Reference, err error) {
	if ref, _, err = g.gh.Git.GetRef(ctx, strings.Split(*reponame, "/")[0], strings.Split(*reponame, "/")[1], "refs/heads/content.update"); err == nil {
		return ref, nil
	}

	// We consider that an error means the branch has not been found and needs to
	// be created.
	var baseRef *github.Reference
	if baseRef, _, err = g.gh.Git.GetRef(ctx, strings.Split(*reponame, "/")[0], strings.Split(*reponame, "/")[1], "refs/heads/master"); err != nil {
		return nil, err
	}
	newRef := &github.Reference{Ref: github.String("refs/heads/content.update"), Object: &github.GitObject{SHA: baseRef.Object.SHA}}
	ref, _, err = g.gh.Git.CreateRef(ctx, strings.Split(*reponame, "/")[0], strings.Split(*reponame, "/")[1], newRef)
	return ref, err
}

func (g *giter) getFiles() ([]string, error) {
	repo, err := git.OpenRepository(*repopath)
	if err != nil {
		return nil, err
	}
	opt := git.StatusOptions{
		Flags: git.StatusOptIncludeUntracked,
	}
	l, err := repo.StatusList(&opt)
	if err != nil {
		return nil, err
	}
	count, err := l.EntryCount()
	if err != nil {
		return nil, err
	}
	fmt.Printf("untracked files count %d", count)

	var list []string
	for i := 0; i < count; i++ {
		status, err := l.ByIndex(i)
		if err != nil {
			return nil, err
		}
		list = append(list, fmt.Sprintf("%s:%s", status.IndexToWorkdir.OldFile.Path, status.IndexToWorkdir.NewFile.Path))
	}

	return list, nil
}

// getTree generates the tree to commit based on the given files and the commit
// of the ref you got in getRef.
func (g *giter) getTree(ctx context.Context, ref *github.Reference) (tree *github.Tree, err error) {
	// Create a tree with what to commit.
	entries := []github.TreeEntry{}
	files, err := g.getFiles()
	if err != nil {
		return nil, err
	}

	// Load each file into the tree.
	for _, fileArg := range files {
		file, content, err := getFileContent(fileArg)
		fmt.Println(file)
		if err != nil {
			return nil, err
		}
		entries = append(entries, github.TreeEntry{Path: github.String(file), Type: github.String("blob"), Content: github.String(string(content)), Mode: github.String("100644")})
	}

	tree, _, err = g.gh.Git.CreateTree(ctx, strings.Split(*reponame, "/")[0], strings.Split(*reponame, "/")[1], *ref.Object.SHA, entries)
	return tree, err
}

// getFileContent loads the local content of a file and return the target name
// of the file in the target repository and its contents.
func getFileContent(fileArg string) (targetName string, b []byte, err error) {
	var localFile string
	files := strings.Split(fileArg, ":")
	switch {
	case len(files) < 1:
		return "", nil, errors.New("no file to commit")
	case len(files) == 1:
		localFile = files[0]
		targetName = files[0]
	default:
		localFile = files[0]
		targetName = files[1]
	}

	b, err = ioutil.ReadFile(localFile)
	return targetName, b, err
}

// pushCommit creates the commit in the given reference using the given tree.
func (g *giter) pushCommit(ctx context.Context, ref *github.Reference, tree *github.Tree) (err error) {
	// Get the parent commit to attach the commit to.
	parent, _, err := g.gh.Repositories.GetCommit(ctx, strings.Split(*reponame, "/")[0], strings.Split(*reponame, "/")[1], *ref.Object.SHA)
	if err != nil {
		return err
	}
	// This is not always populated, but is needed.
	parent.Commit.SHA = parent.SHA

	// Create the commit using the tree.
	date := time.Now()
	author := &github.CommitAuthor{Date: &date, Name: to.StringPtr("arho-bot"), Email: to.StringPtr("aos-azure@redhat.com")}
	commit := &github.Commit{Author: author, Message: to.StringPtr("content update"), Tree: tree, Parents: []github.Commit{*parent.Commit}}
	newCommit, _, err := g.gh.Git.CreateCommit(ctx, strings.Split(*reponame, "/")[0], strings.Split(*reponame, "/")[1], commit)
	if err != nil {
		return err
	}

	// Attach the commit to the master branch.
	ref.Object.SHA = newCommit.SHA
	_, _, err = g.gh.Git.UpdateRef(ctx, strings.Split(*reponame, "/")[0], strings.Split(*reponame, "/")[1], ref, false)
	return err
}

func (g *giter) run(ctx context.Context) error {
	ref, err := g.getRef(ctx)
	if err != nil {
		log.Fatalf("Unable to get/create the commit reference: %s\n", err)
	}
	if ref == nil {
		log.Fatalf("No error where returned but the reference is nil")
	}

	tree, err := g.getTree(ctx, ref)
	if err != nil {
		log.Fatalf("Unable to create the tree based on the provided files: %s\n", err)
	}

	if err := g.pushCommit(ctx, ref, tree); err != nil {
		log.Fatalf("Unable to create the commit: %s\n", err)
	}
	//
	//if err := createPR(); err != nil {
	//	log.Fatalf("Error while creating the pull request: %s", err)
	//}

	return nil
}

func main() {
	ctx := context.Background()

	flag.Parse()

	g, err := newGiter(ctx)
	if err != nil {
		panic(err)
	}
	if err = g.run(ctx); err != nil {
		panic(err)
	}
}
