package main

import (
	"context"
	"encoding/json"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sts/api/pb"
	"testing"
	"time"
)

func testServer() *Server {
	return &Server{store: seed(), lim: &limiter{m: map[string][]time.Time{}, max: 10000, window: time.Minute}, metrics: map[string]int64{}}
}
func req(t *testing.T, s *Server, path, tenant string) (int, []byte) {
	t.Helper()
	r := httptest.NewRequest("GET", path, nil)
	if tenant != "" {
		r.Header.Set("Authorization", "Bearer "+makeToken(tenant))
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	b, _ := io.ReadAll(w.Result().Body)
	return w.Code, b
}

func TestRESTAuthTenantScopeAndPagination(t *testing.T) {
	s := testServer()
	if c, _ := req(t, s, "/v1/events", ""); c != 401 {
		t.Fatalf("want 401 got %d", c)
	}
	if c, _ := req(t, s, "/v1/events?tenant=tenant-2", "tenant-1"); c != 403 {
		t.Fatalf("want 403 got %d", c)
	}
	c, b := req(t, s, "/v1/events?limit=10", "tenant-1")
	if c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	var v struct {
		Events []Event `json:"events"`
		Next   string  `json:"next_cursor"`
	}
	json.Unmarshal(b, &v)
	if len(v.Events) != 10 || v.Next == "" {
		t.Fatalf("page %+v", v)
	}
	c, b = req(t, s, "/v1/events?limit=10&cursor="+v.Next, "tenant-1")
	json.Unmarshal(b, &v)
	_ = c
	c, b = req(t, s, "/v2/incidents", "tenant-1")
	var v2 struct {
		Data []Incident `json:"data"`
	}
	json.Unmarshal(b, &v2)
	if c != 200 || len(v2.Data) != 2 {
		t.Fatalf("v2 %d %s", c, b)
	}
}
func TestRateLimit(t *testing.T) {
	s := testServer()
	s.lim = &limiter{m: map[string][]time.Time{}, max: 2, window: time.Minute}
	req(t, s, "/v1/events", "tenant-1")
	req(t, s, "/v1/events", "tenant-1")
	if c, _ := req(t, s, "/v1/events", "tenant-1"); c != 429 {
		t.Fatalf("want 429 got %d", c)
	}
}

// Contract tests: OpenAPI paths and proto RPCs must be served by the running server.
func TestContractOpenAPIAndProto(t *testing.T) {
	spec, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/v1/events", "/v1/incidents", "/v2/events", "/v2/incidents", "/healthz"} {
		if !strings.Contains(string(spec), p) {
			t.Fatalf("spec missing %s", p)
		}
		if c, _ := req(t, testServer(), p, "tenant-1"); p != "/healthz" && c != 200 {
			t.Fatalf("%s served %d", p, c)
		}
	}
	proto, _ := os.ReadFile("proto/telemetry.proto")
	for _, rpc := range []string{"ListEvents", "ListIncidents", "StreamIncidents"} {
		if !strings.Contains(string(proto), "rpc "+rpc) {
			t.Fatalf("proto missing %s", rpc)
		}
	}
	// live gRPC against the same server implementation
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	gs := grpc.NewServer()
	pb.RegisterTelemetryServiceServer(gs, testServer())
	go gs.Serve(lis)
	defer gs.Stop()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+makeToken("tenant-1"))
	cl := pb.NewTelemetryServiceClient(conn)
	ev, err := cl.ListEvents(ctx, &pb.ListRequest{Tenant: "tenant-1", Limit: 5})
	if err != nil || len(ev.Events) != 5 {
		t.Fatalf("grpc events %v %+v", err, ev)
	}
	stream, err := cl.StreamIncidents(ctx, &pb.ListRequest{Tenant: "tenant-1"})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("streamed %d incidents", n)
	}
	if _, err := cl.ListEvents(context.Background(), &pb.ListRequest{}); err == nil {
		t.Fatal("unauthenticated grpc should fail")
	}
}
func BenchmarkREST(b *testing.B) {
	s := testServer()
	h := s.handler()
	tok := "Bearer " + makeToken("tenant-1")
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("GET", "/v1/events?limit=50", nil)
		r.Header.Set("Authorization", tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			b.Fatal(w.Code)
		}
	}
}
func BenchmarkGRPC(b *testing.B) {
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	gs := grpc.NewServer()
	pb.RegisterTelemetryServiceServer(gs, testServer())
	go gs.Serve(lis)
	defer gs.Stop()
	conn, _ := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+makeToken("tenant-1"))
	cl := pb.NewTelemetryServiceClient(conn)
	for i := 0; i < b.N; i++ {
		if _, err := cl.ListEvents(ctx, &pb.ListRequest{Tenant: "tenant-1", Limit: 50}); err != nil {
			b.Fatal(err)
		}
	}
	fmt.Println()
}

var _ = http.MethodGet
