package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sts/api/pb"
	"sync"
	"time"
)

type Event struct {
	EventID  string `json:"event_id"`
	Tenant   string `json:"tenant"`
	User     string `json:"user"`
	Source   string `json:"source"`
	App      string `json:"app"`
	Category string `json:"category"`
	BytesOut int64  `json:"bytes_out"`
	Verdict  string `json:"verdict"`
	Ts       int64  `json:"ts"`
}
type Incident struct {
	User       string   `json:"user"`
	Tenant     string   `json:"tenant"`
	Confidence float64  `json:"confidence"`
	Summary    string   `json:"summary"`
	Ts         int64    `json:"ts"`
	Signals    []string `json:"signals"`
}

type Store struct {
	mu           sync.RWMutex
	events       []Event
	incidents    []Incident
	cache        map[string]cacheItem
	hits, misses int64
}
type cacheItem struct {
	v   []Incident
	exp time.Time
}

func (s *Store) incidentsFor(tenant string) []Incident { // hot-path cache (Redis if REDIS_ADDR set, else in-process; same TTL semantics)
	if v, ok := redisGet("incidents:" + tenant); ok {
		var out []Incident
		if json.Unmarshal([]byte(v), &out) == nil {
			return out
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.cache["incidents:"+tenant]; ok && time.Now().Before(c.exp) {
		s.hits++
		return c.v
	}
	s.misses++
	var out []Incident
	for _, i := range s.incidents {
		if i.Tenant == tenant {
			out = append(out, i)
		}
	}
	if s.cache == nil {
		s.cache = map[string]cacheItem{}
	}
	s.cache["incidents:"+tenant] = cacheItem{out, time.Now().Add(5 * time.Second)}
	b, _ := json.Marshal(out)
	redisSet("incidents:"+tenant, string(b))
	return out
}
func redisConn() net.Conn {
	a := os.Getenv("REDIS_ADDR")
	if a == "" {
		return nil
	}
	c, err := net.DialTimeout("tcp", a, 200*time.Millisecond)
	if err != nil {
		return nil
	}
	return c
}
func respCmd(c net.Conn, args ...string) string {
	fmt.Fprintf(c, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(c, "$%d\r\n%s\r\n", len(a), a)
	}
	r := bufio.NewReader(c)
	line, _ := r.ReadString('\n')
	if strings.HasPrefix(line, "$") {
		n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
		if n < 0 {
			return ""
		}
		buf := make([]byte, n+2)
		_, err := io_ReadFull(r, buf)
		if err != nil {
			return ""
		}
		return string(buf[:n])
	}
	return strings.TrimSpace(line)
}
func io_ReadFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
func redisGet(k string) (string, bool) {
	c := redisConn()
	if c == nil {
		return "", false
	}
	defer c.Close()
	v := respCmd(c, "GET", k)
	return v, v != ""
}
func redisSet(k, v string) {
	c := redisConn()
	if c == nil {
		return
	}
	defer c.Close()
	respCmd(c, "SETEX", k, "5", v)
}

var secret = env("STS_JWT_SECRET", "dev-secret")

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func makeToken(tenant string) string { // HS256 JWT, stdlib only
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now().Unix()
	p := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"tenant":"%s","sub":"svc","exp":%d}`, tenant, now+3600)))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(h + "." + p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func authTenant(r *http.Request) (string, error) {
	a := r.Header.Get("Authorization")
	if !strings.HasPrefix(a, "Bearer ") {
		return "", fmt.Errorf("missing bearer token")
	}
	parts := strings.Split(strings.TrimPrefix(a, "Bearer "), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("bad token")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal([]byte(base64.RawURLEncoding.EncodeToString(mac.Sum(nil))), []byte(parts[2])) {
		return "", fmt.Errorf("bad signature")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var c struct {
		Tenant string `json:"tenant"`
		Exp    int64  `json:"exp"`
	}
	if json.Unmarshal(b, &c) != nil || c.Tenant == "" || c.Exp < time.Now().Unix() {
		return "", fmt.Errorf("expired/no tenant claim")
	}
	return c.Tenant, nil
}

type limiter struct {
	mu     sync.Mutex
	m      map[string][]time.Time
	max    int
	window time.Duration
}

func (l *limiter) allow(k string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var q []time.Time
	for _, t := range l.m[k] {
		if now.Sub(t) < l.window {
			q = append(q, t)
		}
	}
	if len(q) >= l.max {
		l.m[k] = q
		return false
	}
	l.m[k] = append(q, now)
	return true
}

type Server struct {
	pb.UnimplementedTelemetryServiceServer
	store   *Store
	lim     *limiter
	metrics map[string]int64
	mmu     sync.Mutex
}

func (s *Server) count(k string) { s.mmu.Lock(); s.metrics[k]++; s.mmu.Unlock() }
func cursorOff(c string) int {
	b, _ := base64.RawURLEncoding.DecodeString(c)
	n, _ := strconv.Atoi(string(b))
	return n
}
func cursorFor(n int) string { return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(n))) }
func page[T any](in []T, cursor string, limit int) ([]T, string) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	off := cursorOff(cursor)
	if off > len(in) {
		off = len(in)
	}
	end := off + limit
	if end > len(in) {
		end = len(in)
	}
	next := ""
	if end < len(in) {
		next = cursorFor(end)
	}
	return in[off:end], next
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		s.mmu.Lock()
		defer s.mmu.Unlock()
		for k, v := range s.metrics {
			fmt.Fprintf(w, "sts_%s %d\n", k, v)
		}
		fmt.Fprintf(w, "sts_cache_hits %d\nsts_cache_misses %d\n", s.store.hits, s.store.misses)
	})
	mux.HandleFunc("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		b, _ := os.ReadFile("openapi.yaml")
		if b == nil {
			b, _ = os.ReadFile("../api/openapi.yaml")
		}
		w.Header().Set("Content-Type", "text/yaml")
		w.Write(b)
	})
	events := func(v2 bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { s.serveList(w, r, v2, false) }
	}
	inc := func(v2 bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { s.serveList(w, r, v2, true) }
	}
	mux.HandleFunc("/v1/events", events(false))
	mux.HandleFunc("/v2/events", events(true))
	mux.HandleFunc("/v1/incidents", inc(false))
	mux.HandleFunc("/v2/incidents", inc(true))
	mux.HandleFunc("/v1/token", func(w http.ResponseWriter, r *http.Request) { // dev/demo token endpoint (OAuth2 client-credentials shape); prod: external IdP
		json.NewEncoder(w).Encode(map[string]string{"access_token": makeToken(r.URL.Query().Get("tenant")), "token_type": "Bearer"})
	})
	return s.trace(mux)
}
func (s *Server) trace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // OpenTelemetry traceparent propagation (no SDK dep)
		tp := r.Header.Get("traceparent")
		if tp == "" {
			b := make([]byte, 16)
			rand.Read(b)
			tp = "00-" + hex.EncodeToString(b) + "-0000000000000001-01"
		}
		w.Header().Set("traceparent", tp)
		s.count("requests_total")
		next.ServeHTTP(w, r)
	})
}
func (s *Server) serveList(w http.ResponseWriter, r *http.Request, v2, incidents bool) {
	tenant, err := authTenant(r)
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	if q := r.URL.Query().Get("tenant"); q != "" && q != tenant {
		http.Error(w, "tenant scope violation", 403)
		return
	}
	if !s.lim.allow(tenant) {
		http.Error(w, "rate limited", 429)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	cur := r.URL.Query().Get("cursor")
	w.Header().Set("Content-Type", "application/json")
	if incidents {
		items, next := page(s.store.incidentsFor(tenant), cur, limit)
		if v2 {
			json.NewEncoder(w).Encode(map[string]any{"data": items, "next_cursor": next, "meta": map[string]any{"version": 2}})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"incidents": items, "next_cursor": next})
		}
		return
	}
	s.store.mu.RLock()
	var ev []Event
	for _, e := range s.store.events {
		if e.Tenant == tenant {
			ev = append(ev, e)
		}
	}
	s.store.mu.RUnlock()
	items, next := page(ev, cur, limit)
	if v2 {
		json.NewEncoder(w).Encode(map[string]any{"data": items, "next_cursor": next, "meta": map[string]any{"version": 2}})
	} else {
		json.NewEncoder(w).Encode(map[string]any{"events": items, "next_cursor": next})
	}
}

// gRPC
func grpcTenant(ctx context.Context) (string, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	v := md.Get("authorization")
	if len(v) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing token")
	}
	req := &http.Request{Header: http.Header{"Authorization": v}}
	t, err := authTenant(req)
	if err != nil {
		return "", status.Error(codes.Unauthenticated, err.Error())
	}
	return t, nil
}
func (s *Server) ListEvents(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	t, err := grpcTenant(ctx)
	if err != nil {
		return nil, err
	}
	if req.Tenant != "" && req.Tenant != t {
		return nil, status.Error(codes.PermissionDenied, "tenant scope")
	}
	s.store.mu.RLock()
	var out []*pb.Event
	for _, e := range s.store.events {
		if e.Tenant == t {
			out = append(out, &pb.Event{EventId: e.EventID, Tenant: e.Tenant, User: e.User, Source: e.Source, App: e.App, Category: e.Category, BytesOut: e.BytesOut, Verdict: e.Verdict, Ts: e.Ts})
		}
	}
	s.store.mu.RUnlock()
	items, next := page(out, req.Cursor, int(req.Limit))
	return &pb.ListResponse{Events: items, NextCursor: next}, nil
}
func (s *Server) ListIncidents(ctx context.Context, req *pb.ListRequest) (*pb.IncidentResponse, error) {
	t, err := grpcTenant(ctx)
	if err != nil {
		return nil, err
	}
	var out []*pb.Incident
	for _, i := range s.store.incidentsFor(t) {
		out = append(out, &pb.Incident{User: i.User, Tenant: i.Tenant, Confidence: i.Confidence, Summary: i.Summary, Ts: i.Ts, Signals: i.Signals})
	}
	items, next := page(out, req.Cursor, int(req.Limit))
	return &pb.IncidentResponse{Incidents: items, NextCursor: next}, nil
}
func (s *Server) StreamIncidents(req *pb.ListRequest, stream pb.TelemetryService_StreamIncidentsServer) error {
	t, err := grpcTenant(stream.Context())
	if err != nil {
		return err
	}
	for _, i := range s.store.incidentsFor(t) {
		if err := stream.Send(&pb.Incident{User: i.User, Tenant: i.Tenant, Confidence: i.Confidence, Summary: i.Summary, Ts: i.Ts, Signals: i.Signals}); err != nil {
			return err
		}
	}
	return nil
}

func seed() *Store {
	st := &Store{cache: map[string]cacheItem{}}
	if f := os.Getenv("STS_DATA_FILE"); f != "" {
		if fh, err := os.Open(f); err == nil {
			defer fh.Close()
			sc := bufio.NewScanner(fh)
			sc.Buffer(make([]byte, 1024*1024), 1024*1024)
			for sc.Scan() {
				var e Event
				if json.Unmarshal(sc.Bytes(), &e) == nil && e.EventID != "" {
					st.events = append(st.events, e)
				}
			}
		}
	}
	if len(st.events) == 0 {
		for i := 0; i < 300; i++ {
			st.events = append(st.events, Event{fmt.Sprintf("e-%d", i), "tenant-1", fmt.Sprintf("user-%d", i%20), "PROXY", "mail", "business", 1000, "allow", 1700000000000 + int64(i*1000)})
		}
	}
	st.incidents = []Incident{{"victim-dns-0", "tenant-1", 0.97, "dns_tunneling@DNS", 1700000100000, []string{"dns_tunneling@DNS"}}, {"victim-exfil-0", "tenant-1", 0.95, "data_exfiltration@PROXY", 1700000200000, []string{"data_exfiltration@PROXY"}}}
	sort.Slice(st.events, func(i, j int) bool { return st.events[i].Ts < st.events[j].Ts })
	return st
}
func main() {
	s := &Server{store: seed(), lim: &limiter{m: map[string][]time.Time{}, max: 1000, window: time.Minute}, metrics: map[string]int64{}}
	go func() {
		lis, err := net.Listen("tcp", env("GRPC_ADDR", ":50051"))
		if err != nil {
			log.Fatal(err)
		}
		gs := grpc.NewServer()
		pb.RegisterTelemetryServiceServer(gs, s)
		log.Println("grpc on", lis.Addr())
		log.Fatal(gs.Serve(lis))
	}()
	log.Println("rest on", env("HTTP_ADDR", ":8080"))
	log.Fatal(http.ListenAndServe(env("HTTP_ADDR", ":8080"), s.handler()))
}

var _ = context.Background
