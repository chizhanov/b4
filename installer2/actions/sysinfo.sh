#!/bin/sh
# Action: Show system diagnostics

action_sysinfo() {
    log_header "B4 System Diagnostics"

    # --- System info ---
    log_sep
    log_detail "Hostname" "$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo 'unknown')"
    log_detail "Kernel" "$(uname -r)"
    log_detail "Architecture (raw)" "$(uname -m)"
    log_detail "Architecture (b4)" "$(detect_architecture 2>/dev/null || echo 'unknown')"
    [ -f /etc/os-release ] && log_detail "Distribution" "$(. /etc/os-release && echo "$PRETTY_NAME")"
    [ -f /etc/openwrt_release ] && log_detail "OpenWrt" "$(. /etc/openwrt_release && echo "$DISTRIB_DESCRIPTION")"

    # CPU
    cpu_cores=""
    if [ -f /proc/cpuinfo ]; then
        cpu_cores=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null)
    fi
    [ -n "$cpu_cores" ] && log_detail "CPU cores" "$cpu_cores"

    # Memory
    if [ -f /proc/meminfo ]; then
        mem_total=$(awk '/^MemTotal:/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
        mem_avail=$(awk '/^MemAvailable:/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
        [ -z "$mem_avail" ] && mem_avail=$(awk '/^MemFree:/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
        if [ -n "$mem_total" ]; then
            log_detail "Memory" "${mem_total} MB (Available: ${mem_avail:-?} MB)"
        fi
    fi

    # Platform detection
    platform_auto_detect 2>/dev/null || true
    if [ -n "$B4_PLATFORM" ]; then
        pname=$(platform_dispatch "$B4_PLATFORM" name 2>/dev/null)
        log_detail "Detected platform" "${pname} (${B4_PLATFORM})"
        platform_call info 2>/dev/null || true
        log_detail "Binary dir" "${B4_BIN_DIR}"
        log_detail "Data dir" "${B4_DATA_DIR}"
        log_detail "Service type" "${B4_SERVICE_TYPE}"
    fi

    # --- B4 status ---
    log_sep

    found_bin=""
    for dir in "$B4_BIN_DIR" /usr/local/bin /usr/bin /usr/sbin /opt/bin /opt/sbin /tmp/b4; do
        [ -z "$dir" ] && continue
        if [ -f "${dir}/${BINARY_NAME}" ]; then
            found_bin="${dir}/${BINARY_NAME}"
            break
        fi
    done

    if [ -n "$found_bin" ]; then
        log_detail "Binary" "$found_bin"
        ver=$("$found_bin" --version 2>&1 | head -1) || ver="unknown"
        log_detail "Version" "$ver"
    else
        log_detail "Binary" "${RED}not found${NC}"
    fi

    # Config file
    cfg_file=""
    for cfg in "$B4_CONFIG_FILE" /etc/b4/b4.json /opt/etc/b4/b4.json; do
        [ -z "$cfg" ] && continue
        [ -f "$cfg" ] && cfg_file="$cfg" && break
    done
    [ -n "$cfg_file" ] && log_detail "Config" "$cfg_file"

    # Running status + details from config and process
    if is_b4_running; then
        log_detail "Service status" "${GREEN}running${NC}"

        # Get PID and process details
        b4_pid=""
        for pf in /var/run/b4.pid /opt/var/run/b4.pid; do
            if [ -f "$pf" ] && kill -0 "$(cat "$pf")" 2>/dev/null; then
                b4_pid=$(cat "$pf")
                break
            fi
        done
        [ -z "$b4_pid" ] && b4_pid=$(pgrep -x "$BINARY_NAME" 2>/dev/null | head -1)
        [ -z "$b4_pid" ] && b4_pid=$(pgrep -f "${BINARY_NAME}" 2>/dev/null | head -1)

        if [ -n "$b4_pid" ]; then
            # Memory usage
            if [ -f "/proc/${b4_pid}/status" ]; then
                mem_kb=$(awk '/^VmRSS:/ {print $2}' "/proc/${b4_pid}/status" 2>/dev/null)
                if [ -n "$mem_kb" ]; then
                    mem_mb=$(awk "BEGIN {printf \"%.1f\", $mem_kb/1024}")
                    log_detail "Memory usage" "${mem_mb} MB (PID: ${b4_pid})"
                fi
            fi

            # Uptime
            if [ -f "/proc/${b4_pid}/stat" ]; then
                proc_start=$(awk '{print $22}' "/proc/${b4_pid}/stat" 2>/dev/null)
                clk_tck=$(getconf CLK_TCK 2>/dev/null || echo 100)
                sys_uptime=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
                if [ -n "$proc_start" ] && [ -n "$sys_uptime" ] && [ "$clk_tck" -gt 0 ] 2>/dev/null; then
                    proc_secs=$((proc_start / clk_tck))
                    running_secs=$((sys_uptime - proc_secs))
                    if [ "$running_secs" -ge 3600 ] 2>/dev/null; then
                        hours=$((running_secs / 3600))
                        mins=$(( (running_secs % 3600) / 60 ))
                        log_detail "Uptime" "${hours}h ${mins}m"
                    elif [ "$running_secs" -ge 60 ] 2>/dev/null; then
                        mins=$((running_secs / 60))
                        log_detail "Uptime" "${mins}m"
                    elif [ "$running_secs" -ge 0 ] 2>/dev/null; then
                        log_detail "Uptime" "${running_secs}s"
                    fi
                fi
            fi
        fi
    else
        log_detail "Service status" "${YELLOW}not running${NC}"
    fi

    # Config-derived info (queue number, worker threads, geodat paths)
    if [ -n "$cfg_file" ] && command_exists jq; then
        queue_num=$(jq -r '.system.queue_num // empty' "$cfg_file" 2>/dev/null)
        workers=$(jq -r '.system.workers // empty' "$cfg_file" 2>/dev/null)
        geosite=$(jq -r '.system.geo.sitedat_path // empty' "$cfg_file" 2>/dev/null)
        geoip=$(jq -r '.system.geo.ipdat_path // empty' "$cfg_file" 2>/dev/null)

        [ -n "$queue_num" ] && [ "$queue_num" != "null" ] && log_detail "Queue number" "$queue_num"
        [ -n "$workers" ] && [ "$workers" != "null" ] && log_detail "Worker threads" "$workers"

        if [ -n "$geosite" ] && [ "$geosite" != "null" ] && [ -f "$geosite" ]; then
            size=$(ls -lh "$geosite" 2>/dev/null | awk '{print $5}')
            log_detail "geosite.dat" "${geosite} (${size})"
        fi
        if [ -n "$geoip" ] && [ "$geoip" != "null" ] && [ -f "$geoip" ]; then
            size=$(ls -lh "$geoip" 2>/dev/null | awk '{print $5}')
            log_detail "geoip.dat" "${geoip} (${size})"
        fi
    fi

    log_sep

    # --- Kernel modules ---
    echo ""
    log_info "Kernel modules:"
    for mod in xt_NFQUEUE nfnetlink_queue xt_connbytes xt_multiport nf_conntrack; do
        if lsmod 2>/dev/null | grep -q "^${mod}"; then
            printf "    ${GREEN}loaded${NC}   %s\n" "$mod" >&2
        elif _kmod_builtin "$mod"; then
            printf "    ${GREEN}built-in${NC} %s\n" "$mod" >&2
        else
            printf "    ${YELLOW}missing${NC}  %s ${DIM}(may be built-in)${NC}\n" "$mod" >&2
        fi
    done

    # Functional test — does NFQUEUE actually work?
    if command_exists iptables; then
        if iptables -t mangle -C B4_TEST -j NFQUEUE --queue-num 0 2>/dev/null; then
            iptables -t mangle -D B4_TEST -j NFQUEUE --queue-num 0 2>/dev/null || true
        fi
        if iptables -t mangle -N B4_TEST 2>/dev/null; then
            if iptables -t mangle -A B4_TEST -j NFQUEUE --queue-num 0 2>/dev/null; then
                printf "    ${GREEN}  OK${NC}    %s\n" "NFQUEUE works (functional test passed)" >&2
                iptables -t mangle -D B4_TEST -j NFQUEUE --queue-num 0 2>/dev/null || true
            else
                printf "    ${RED}  FAIL${NC}  %s\n" "NFQUEUE not functional" >&2
            fi
            iptables -t mangle -X B4_TEST 2>/dev/null || true
        fi
    fi

    # --- Network tools ---
    echo ""
    log_info "Network tools:"
    for tool in iptables nft jq tar sha256sum; do
        if command_exists "$tool"; then
            printf "    ${GREEN}found${NC}   %s\n" "$tool" >&2
        else
            printf "    ${YELLOW}missing${NC} %s\n" "$tool" >&2
        fi
    done

    # curl/wget with HTTPS check
    if command_exists curl; then
        if curl -sI --max-time 5 "https://github.com" >/dev/null 2>&1; then
            printf "    ${GREEN}found${NC}   curl ${GREEN}(HTTPS OK)${NC}\n" >&2
        else
            printf "    ${YELLOW}found${NC}   curl ${RED}(HTTPS failed)${NC}\n" >&2
        fi
    else
        printf "    ${YELLOW}missing${NC} curl\n" >&2
    fi
    if command_exists wget; then
        if wget --spider -q --timeout=5 "https://github.com" 2>/dev/null; then
            printf "    ${GREEN}found${NC}   wget ${GREEN}(HTTPS OK)${NC}\n" >&2
        elif wget --spider -q --timeout=5 --no-check-certificate "https://github.com" 2>/dev/null; then
            printf "    ${YELLOW}found${NC}   wget ${YELLOW}(HTTPS only with --no-check-certificate)${NC}\n" >&2
        else
            printf "    ${YELLOW}found${NC}   wget ${RED}(HTTPS failed)${NC}\n" >&2
        fi
    else
        printf "    ${YELLOW}missing${NC} wget\n" >&2
    fi

    # Package manager
    echo ""
    detect_pkg_manager
    log_detail "Package manager" "${B4_PKG_MANAGER:-none}"

    # --- Storage ---
    echo ""
    log_info "Storage:"
    for dir in / /opt /tmp /jffs /mnt/sda1 /etc/storage; do
        if [ -d "$dir" ]; then
            avail=$(df -h "$dir" 2>/dev/null | tail -1 | awk '{print $4}')
            writable="rw"
            [ ! -w "$dir" ] && writable="ro"
            printf "    %-15s %s available (%s)\n" "$dir" "${avail:-?}" "$writable" >&2
        fi
    done

    echo ""
    log_sep
}

# Check if a kernel module is built-in (not loadable but compiled into kernel)
_kmod_builtin() {
    mod="$1"
    kver=$(uname -r)
    # Check modules.builtin file (lists built-in modules)
    for f in "/lib/modules/${kver}/modules.builtin" "/lib/modules/${kver}/modules.builtin.modinfo"; do
        [ -f "$f" ] && grep -q "${mod}" "$f" 2>/dev/null && return 0
    done
    # Check /sys/module — exists for both loaded and built-in modules
    [ -d "/sys/module/${mod}" ] && return 0
    return 1
}
