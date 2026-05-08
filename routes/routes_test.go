package routes

import (
	"api/internal/config"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSimulationHighErrorRateProfile(t *testing.T) {
	router := SetupRouter(nil, config.Config{
		ServiceName: "june-api",
		SimEnabled:  true,
		SimProfile:  "high-error-rate",
	})

	for i := 1; i <= 4; i++ {
		resp := request(router, http.MethodGet, "/api/v1/sim/work")
		if resp.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want %d", i, resp.Code, http.StatusOK)
		}
	}

	resp := request(router, http.MethodGet, "/api/v1/sim/work")
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("fifth request status = %d, want %d", resp.Code, http.StatusInternalServerError)
	}
}

func TestSimulationProbeInstabilityProfile(t *testing.T) {
	router := SetupRouter(nil, config.Config{
		ServiceName: "june-api",
		SimEnabled:  true,
		SimProfile:  "probe-instability",
	})

	resp := request(router, http.MethodGet, "/ready")
	if resp.Code != http.StatusOK {
		t.Fatalf("first readiness status = %d, want %d", resp.Code, http.StatusOK)
	}

	resp = request(router, http.MethodGet, "/ready")
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("second readiness status = %d, want %d", resp.Code, http.StatusServiceUnavailable)
	}
}

func request(handler http.Handler, method string, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	return resp
}
