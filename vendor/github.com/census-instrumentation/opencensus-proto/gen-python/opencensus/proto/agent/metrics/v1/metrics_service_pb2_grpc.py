# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
import grpc

from opencensus.proto.agent.metrics.v1 import metrics_service_pb2 as opencensus_dot_proto_dot_agent_dot_metrics_dot_v1_dot_metrics__service__pb2


class MetricsServiceStub(object):
  """Service that can be used to push metrics between one Application
  instrumented with OpenCensus and an agent, or between an agent and a
  central collector.
  """

  def __init__(self, channel):
    """Constructor.

    Args:
      channel: A grpc.Channel.
    """
    self.Export = channel.stream_stream(
        '/opencensus.proto.agent.metrics.v1.MetricsService/Export',
        request_serializer=opencensus_dot_proto_dot_agent_dot_metrics_dot_v1_dot_metrics__service__pb2.ExportMetricsServiceRequest.SerializeToString,
        response_deserializer=opencensus_dot_proto_dot_agent_dot_metrics_dot_v1_dot_metrics__service__pb2.ExportMetricsServiceResponse.FromString,
        )


class MetricsServiceServicer(object):
  """Service that can be used to push metrics between one Application
  instrumented with OpenCensus and an agent, or between an agent and a
  central collector.
  """

  def Export(self, request_iterator, context):
    """For performance reasons, it is recommended to keep this RPC
    alive for the entire life of the application.
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')


def add_MetricsServiceServicer_to_server(servicer, server):
  rpc_method_handlers = {
      'Export': grpc.stream_stream_rpc_method_handler(
          servicer.Export,
          request_deserializer=opencensus_dot_proto_dot_agent_dot_metrics_dot_v1_dot_metrics__service__pb2.ExportMetricsServiceRequest.FromString,
          response_serializer=opencensus_dot_proto_dot_agent_dot_metrics_dot_v1_dot_metrics__service__pb2.ExportMetricsServiceResponse.SerializeToString,
      ),
  }
  generic_handler = grpc.method_handlers_generic_handler(
      'opencensus.proto.agent.metrics.v1.MetricsService', rpc_method_handlers)
  server.add_generic_rpc_handlers((generic_handler,))