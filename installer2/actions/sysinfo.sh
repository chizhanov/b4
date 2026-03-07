#!/bin/sh
# Action: Show system diagnostics

action_sysinfo() {
    log_header "B4 System Diagnostics"
    log_sep

    # OS info
    log_detail "OS" "$(uname -s) $(uname -r)"
    log_detail "Architecture" "$(uname -m)"
    [ -f /etc/os-release ] && log_detail "Distribution" "$(. /etc/os-release && echo "$PRETTY_NAME")"
    [ -f /etc/openwrt_release ] && log_detail "OpenWrt" "$(. /etc/openwrt_release && echo "$DISTRIB_DESCRIPTION")"

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

    log_sep

    # B4 installation status
    found_bin=""
    for dir in /usr/local/bin /usr/bin /usr/sbin /opt/bin /opt/sbin /tmp/b4; do
        if [ -f "${dir}/${BINARY_NAME}" ]; then
            found_bin="${dir}/${BINARY_NAME}"
            ver=$("$found_bin" --version 2>&1 | head -1) || ver="unknown"
            log_detail "B4 binary" "${found_bin} (${ver})"
            break
        fi
    done
    [ -z "$found_bin" ] && log_detail "B4 binary" "${RED}not found${NC}"

    if is_b4_running; then
        log_detail "B4 status" "${GREEN}running${NC}"
    else
        log_detail "B4 status" "${YELLOW}not running${NC}"
    fi

    # Config
    for cfg in /etc/b4/b4.json /opt/etc/b4/b4.json; do
        [ -f "$cfg" ] && log_detail "Config" "$cfg" && break
    done

    log_sep

    # Kernel modules
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

    # Network tools
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

    # Storage
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
