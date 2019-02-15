package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/openshift/openshift-azure/pkg/api"
	"github.com/openshift/openshift-azure/pkg/cluster/updateblob"
	"github.com/openshift/openshift-azure/pkg/util/mocks/mock_azureclient/mock_storage"
)

func TestInitialize(t *testing.T) {
	gmc := gomock.NewController(t)
	defer gmc.Finish()
	storageClient := mock_storage.NewMockClient(gmc)
	u := &simpleUpgrader{
		storageClient: storageClient,
	}
	bsa := mock_storage.NewMockBlobStorageClient(gmc)
	storageClient.EXPECT().GetBlobService().Return(bsa)

	etcdCr := mock_storage.NewMockContainer(gmc)
	bsa.EXPECT().GetContainerReference(EtcdBackupContainerName).Return(etcdCr)
	etcdCr.EXPECT().CreateIfNotExists(nil).Return(true, nil)

	updateCr := mock_storage.NewMockContainer(gmc)
	bsa.EXPECT().GetContainerReference(updateblob.UpdateContainerName).Return(updateCr)
	updateCr.EXPECT().CreateIfNotExists(nil).Return(true, nil)

	configCr := mock_storage.NewMockContainer(gmc)
	bsa.EXPECT().GetContainerReference(ConfigContainerName).Return(configCr)
	configCr.EXPECT().CreateIfNotExists(nil).Return(true, nil)

	configBlob := mock_storage.NewMockBlob(gmc)
	configCr.EXPECT().GetBlobReference(ConfigBlobName).Return(configBlob)

	cs := &api.OpenShiftManagedCluster{}
	csj, err := json.Marshal(cs)
	if err != nil {
		t.Fatal(err)
	}
	configBlob.EXPECT().CreateBlockBlobFromReader(bytes.NewReader(csj), nil).Return(nil)

	if err := u.Initialize(context.Background(), cs); err != nil {
		t.Errorf("simpleUpgrader.Initialize() error = %v", err)
	}
}
