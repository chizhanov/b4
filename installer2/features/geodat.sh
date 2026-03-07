#!/bin/sh
# Feature: GeoData files (geosite.dat + geoip.dat)
# Downloads v2ray-format geo databases for domain/IP categorization

GEODAT_SOURCES="1|Loyalsoldier|https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download
2|RUNET Freedom (recommended)|https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release
3|Nidelon|https://github.com/Nidelon/ru-block-v2ray-rules/releases/latest/download
4|DustinWin|https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo
5|Chocolate4U|https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release"

feature_geodat_name() {
    echo "GeoData files"
}

feature_geodat_description() {
    echo "Download geosite.dat & geoip.dat for domain/IP filtering"
}

feature_geodat_default_enabled() {
    echo "yes"
}

feature_geodat_run() {
    log_sep
    echo ""

    # Select source
    echo "  Available geodata sources:"
    echo "$GEODAT_SOURCES" | while IFS='|' read -r num name _url; do
        [ -n "$num" ] && printf "    ${BOLD}%s${NC}) %s\n" "$num" "$name"
    done
    echo ""

    read_input "Select source [2]: " "2"

    base_url=$(echo "$GEODAT_SOURCES" | grep "^${_INPUT}|" | cut -d'|' -f3)
    if [ -z "$base_url" ]; then
        log_warn "Invalid selection, using default"
        base_url=$(echo "$GEODAT_SOURCES" | grep "^2|" | cut -d'|' -f3)
    fi

    # Destination directory
    save_dir="$B4_DATA_DIR"

    # Check if config already has a geodat path
    if [ -f "$B4_CONFIG_FILE" ] && command_exists jq; then
        existing=$(jq -r '.system.geo.sitedat_path // empty' "$B4_CONFIG_FILE" 2>/dev/null)
        if [ -n "$existing" ] && [ "$existing" != "null" ]; then
            save_dir=$(dirname "$existing")
            log_info "Found existing geodat path: $save_dir"
        fi
    fi

    read_input "Save directory [${save_dir}]: " "$save_dir"
    save_dir="$_INPUT"

    ensure_dir "$save_dir" "Geodat directory" || return 1

    # Download files
    log_info "Downloading geosite.dat..."
    if ! fetch_file "${base_url}/geosite.dat" "${save_dir}/geosite.dat"; then
        log_err "Failed to download geosite.dat"
        return 1
    fi
    [ ! -s "${save_dir}/geosite.dat" ] && log_err "geosite.dat is empty" && return 1

    log_info "Downloading geoip.dat..."
    if ! fetch_file "${base_url}/geoip.dat" "${save_dir}/geoip.dat"; then
        log_err "Failed to download geoip.dat"
        return 1
    fi
    [ ! -s "${save_dir}/geoip.dat" ] && log_err "geoip.dat is empty" && return 1

    log_ok "GeoData downloaded to ${save_dir}"

    # Update config
    _geodat_update_config "${save_dir}/geosite.dat" "${save_dir}/geoip.dat" "$base_url"
}

_geodat_update_config() {
    sitedat_path="$1"
    ipdat_path="$2"
    base_url="$3"

    if ! command_exists jq; then
        log_warn "jq not found — please update config manually:"
        log_info "  Set system.geo.sitedat_path = $sitedat_path"
        log_info "  Set system.geo.ipdat_path = $ipdat_path"
        return 0
    fi

    if [ ! -f "$B4_CONFIG_FILE" ]; then
        # Create minimal config
        jq -n \
            --arg sp "$sitedat_path" \
            --arg su "${base_url}/geosite.dat" \
            --arg ip "$ipdat_path" \
            --arg iu "${base_url}/geoip.dat" \
            '{ system: { geo: { sitedat_path: $sp, sitedat_url: $su, ipdat_path: $ip, ipdat_url: $iu } } }' \
            >"$B4_CONFIG_FILE"
        log_ok "Created config with geodat paths"
        return 0
    fi

    # Update existing config
    tmp="${B4_CONFIG_FILE}.tmp"
    if jq \
        --arg sp "$sitedat_path" \
        --arg su "${base_url}/geosite.dat" \
        --arg ip "$ipdat_path" \
        --arg iu "${base_url}/geoip.dat" \
        '.system.geo = (.system.geo // {}) + { sitedat_path: $sp, sitedat_url: $su, ipdat_path: $ip, ipdat_url: $iu }' \
        "$B4_CONFIG_FILE" >"$tmp" 2>/dev/null; then
        mv "$tmp" "$B4_CONFIG_FILE"
        log_ok "Config updated with geodat paths"
    else
        rm -f "$tmp"
        log_warn "Failed to update config, please set paths manually"
    fi
}

feature_geodat_remove() {
    # Read actual geodat paths from config (wherever user put them)
    for cfg in "$B4_CONFIG_FILE" /etc/b4/b4.json /opt/etc/b4/b4.json; do
        [ -f "$cfg" ] || continue
        if command_exists jq; then
            sitedat=$(jq -r '.system.geo.sitedat_path // empty' "$cfg" 2>/dev/null)
            ipdat=$(jq -r '.system.geo.ipdat_path // empty' "$cfg" 2>/dev/null)
            if [ -n "$sitedat" ] || [ -n "$ipdat" ]; then
                _geodat_remove_files "$sitedat" "$ipdat"
                return 0
            fi
        fi
    done

    # Fallback: check default locations
    _geodat_remove_files "/etc/b4/geosite.dat" "/etc/b4/geoip.dat"
    _geodat_remove_files "/opt/etc/b4/geosite.dat" "/opt/etc/b4/geoip.dat"
}

_geodat_remove_files() {
    sitedat="$1"
    ipdat="$2"
    found=""
    [ -n "$sitedat" ] && [ -f "$sitedat" ] && found="${found} ${sitedat}"
    [ -n "$ipdat" ] && [ -f "$ipdat" ] && found="${found} ${ipdat}"
    [ -z "$found" ] && return 0

    log_info "Found geodata files:${found}"
    if [ "$QUIET_MODE" -eq 1 ] || confirm "Remove geodata files?" "y"; then
        for f in $found; do
            rm -f "$f" && log_info "Removed: $f"
        done
    else
        log_info "Keeping geodata files"
    fi
}

register_feature "geodat"
