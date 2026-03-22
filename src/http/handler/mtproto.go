package handler

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/mtproto"
)

func (api *API) RegisterMTProtoApi() {
	api.mux.HandleFunc("/api/mtproto/generate-secret", api.handleMTProtoGenerateSecret)
	api.mux.HandleFunc("/api/mtproto/config", api.handleMTProtoConfig)
}

func (api *API) handleMTProtoGenerateSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		FakeSNI string `json:"fake_sni"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.FakeSNI == "" {
		writeJsonError(w, http.StatusBadRequest, "fake_sni is required")
		return
	}

	sec, err := mtproto.GenerateSecret(req.FakeSNI)
	if err != nil {
		writeJsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	sendResponse(w, map[string]interface{}{
		"success": true,
		"secret":  sec.Hex(),
	})
}

func (api *API) handleMTProtoConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sendResponse(w, map[string]interface{}{
			"success": true,
			"config":  api.cfg.System.MTProto,
		})
	case http.MethodPost:
		api.updateMTProtoConfig(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (api *API) updateMTProtoConfig(w http.ResponseWriter, r *http.Request) {
	var req config.MTProtoConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Port < 1 || req.Port > 65535 {
		writeJsonError(w, http.StatusBadRequest, "Port must be between 1 and 65535")
		return
	}

	if req.BindAddress != "" {
		if net.ParseIP(req.BindAddress) == nil {
			writeJsonError(w, http.StatusBadRequest, "Invalid bind address")
			return
		}
	}

	if req.Secret != "" {
		if _, err := mtproto.ParseSecret(req.Secret); err != nil {
			writeJsonError(w, http.StatusBadRequest, "Invalid secret: "+err.Error())
			return
		}
	}

	api.cfg.System.MTProto = req

	if err := api.cfg.SaveToFile(api.cfg.ConfigPath); err != nil {
		log.Errorf("Failed to save MTProto config: %v", err)
		writeJsonError(w, http.StatusInternalServerError, "Failed to save configuration")
		return
	}

	log.Infof("MTProto configuration updated: enabled=%v, port=%d", req.Enabled, req.Port)

	sendResponse(w, map[string]interface{}{
		"success": true,
		"message": "MTProto configuration updated. Restart required for changes to take effect.",
	})
}
