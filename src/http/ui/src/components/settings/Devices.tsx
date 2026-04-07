import { useState, useEffect } from "react";
import {
  Grid,
  Box,
  Typography,
  Chip,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Checkbox,
  Paper,
  IconButton,
  TextField,
  Button,
} from "@mui/material";
import { useTranslation } from "react-i18next";
import { Device } from "@models/config";
import { DeviceUnknowIcon, RefreshIcon, AddIcon, DeleteIcon } from "@b4.icons";
import EditIcon from "@mui/icons-material/Edit";
import { colors } from "@design";
import {
  B4Section,
  B4Switch,
  B4Alert,
  B4TooltipButton,
  B4Badge,
  B4InlineEdit,
} from "@b4.elements";
import { useDevices, DevicesSettingsProps } from "@b4.devices";
import { sortDevices } from "@utils";

const generateSyntheticMAC = (ip: string): string => {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return "";
  const octets = parts.map((p) => {
    if (!/^\d+$/.test(p)) return -1;
    const n = Number(p);
    return n >= 0 && n <= 255 ? n : -1;
  });
  if (octets.some((o) => o < 0)) return "";
  return `02:B4:${octets.map((o) => o.toString(16).toUpperCase().padStart(2, "0")).join(":")}`;
};

export const DevicesSettings = ({ config, onChange }: DevicesSettingsProps) => {
  const [editingMac, setEditingMac] = useState<string | null>(null);
  const [manualIp, setManualIp] = useState("");
  const [manualName, setManualName] = useState("");
  const { t } = useTranslation();

  const configDevices: Device[] = config.queue.devices?.devices || [];
  const enabled = config.queue.devices?.enabled || false;
  const vendorLookup = config.queue.devices?.vendor_lookup || false;
  const wisb = config.queue.devices?.wisb || false;
  const {
    devices,
    loading,
    available,
    source,
    loadDevices,
  } = useDevices();

  useEffect(() => {
    loadDevices().catch(() => {});
  }, [loadDevices]);

  const findConfigDevice = (mac: string): Device | undefined =>
    configDevices.find((d) => d.mac.toUpperCase() === mac.toUpperCase());

  const updateDevice = (mac: string, update: Partial<Device>) => {
    const current = [...configDevices];
    const idx = current.findIndex((d) => d.mac.toUpperCase() === mac.toUpperCase());
    if (idx === -1) {
      current.push({ mac: mac.toUpperCase(), selected: false, ...update });
    } else {
      current[idx] = { ...current[idx], ...update };
    }
    const cleaned = current.filter(
      (d) => d.selected || d.is_manual || (d.mss_clamp && d.mss_clamp > 0) || d.name
    );
    onChange("queue.devices.devices", cleaned);
  };

  const handleToggle = (mac: string) => {
    const existing = findConfigDevice(mac);
    updateDevice(mac, { selected: !(existing?.selected) });
  };

  const handleSelectAll = (selectAll: boolean) => {
    const current = [...configDevices];
    const allMacs = new Set(devices.map((d) => d.mac.toUpperCase()));
    const updated = current.map((d) =>
      allMacs.has(d.mac.toUpperCase()) ? { ...d, selected: selectAll } : d
    );
    if (selectAll) {
      for (const d of devices) {
        if (!updated.some((u) => u.mac.toUpperCase() === d.mac.toUpperCase())) {
          updated.push({ mac: d.mac.toUpperCase(), selected: true });
        }
      }
    }
    const cleaned = updated.filter(
      (d) => d.selected || d.is_manual || (d.mss_clamp && d.mss_clamp > 0) || d.name
    );
    onChange("queue.devices.devices", cleaned);
  };

  const handleAddManualDevice = () => {
    const ip = manualIp.trim();
    if (!ip) return;
    const mac = generateSyntheticMAC(ip);
    if (!mac) return;
    if (configDevices.some((d) => d.mac.toUpperCase() === mac.toUpperCase())) return;
    const updated = [...configDevices, {
      mac: mac.toUpperCase(),
      ip,
      name: manualName.trim() || undefined,
      selected: false,
      is_manual: true,
    }];
    onChange("queue.devices.devices", updated);
    setManualIp("");
    setManualName("");
  };

  const handleRemoveManualDevice = (mac: string) => {
    onChange("queue.devices.devices", configDevices.filter(
      (d) => d.mac.toUpperCase() !== mac.toUpperCase()
    ));
  };

  const isSelected = (mac: string) => findConfigDevice(mac)?.selected || false;
  const allSelected = devices.length > 0 && devices.every((d) => isSelected(d.mac));
  const someSelected = devices.some((d) => isSelected(d.mac)) && !allSelected;
  const manualDevices = configDevices.filter((d) => d.is_manual);

  const tableHeaders = [
    t("core.devices.macAddress"),
    t("core.devices.ip"),
    t("core.devices.deviceName"),
    t("settings.Devices.mss"),
  ];

  return (
    <B4Section
      title={t("settings.Devices.title")}
      description={t("settings.Devices.description")}
      icon={<DeviceUnknowIcon />}
    >
      <Grid container spacing={2}>
        <Grid size={{ xs: 12 }}>
          <Box
            sx={{
              display: "flex",
              gap: 3,
              alignItems: "center",
              flexWrap: "wrap",
            }}
          >
            <B4Switch
              label={t("settings.Devices.enable")}
              checked={enabled}
              onChange={(checked) => onChange("queue.devices.enabled", checked)}
              description={t("settings.Devices.enableDesc")}
            />
            <B4Switch
              label={t("settings.Devices.vendorLookup")}
              checked={vendorLookup}
              onChange={(checked) =>
                onChange("queue.devices.vendor_lookup", checked)
              }
              description={t("settings.Devices.vendorLookupDesc")}
            />
            <B4Switch
              label={t("settings.Devices.invertSelection")}
              checked={wisb}
              onChange={(checked) => onChange("queue.devices.wisb", checked)}
              description={
                wisb ? t("settings.Devices.invertBlacklist") : t("settings.Devices.invertWhitelist")
              }
              disabled={!enabled}
            />
          </Box>
        </Grid>

        {enabled && (
          <>
            <B4Alert severity={wisb ? "warning" : "info"}>
              {wisb
                ? t("settings.Devices.blacklistAlert")
                : t("settings.Devices.whitelistAlert")}
            </B4Alert>

            {available ? (
              <Grid size={{ xs: 12 }}>
                <Box
                  sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    mb: 1,
                  }}
                >
                  <Typography variant="subtitle2">
                    {t("core.devices.availableDevices")}
                    {source && (
                      <Chip
                        label={source}
                        size="small"
                        sx={{
                          ml: 1,
                          bgcolor: colors.accent.secondary,
                          color: colors.secondary,
                        }}
                      />
                    )}
                  </Typography>
                  <B4TooltipButton
                    title={t("core.devices.refreshDevices")}
                    icon={
                      loading ? <CircularProgress size={18} /> : <RefreshIcon />
                    }
                    onClick={() => {
                      loadDevices().catch(() => {});
                    }}
                  />
                </Box>

                <TableContainer
                  component={Paper}
                  sx={{
                    bgcolor: colors.background.paper,
                    border: `1px solid ${colors.border.default}`,
                    maxHeight: 300,
                  }}
                >
                  <Table size="small" stickyHeader>
                    <TableHead>
                      <TableRow>
                        <TableCell
                          padding="checkbox"
                          sx={{ bgcolor: colors.background.dark }}
                        >
                          <Checkbox
                            color="secondary"
                            indeterminate={someSelected}
                            checked={allSelected}
                            onChange={(e) => handleSelectAll(e.target.checked)}
                          />
                        </TableCell>
                        {tableHeaders.map((label) => (
                          <TableCell
                            key={label}
                            sx={{
                              bgcolor: colors.background.dark,
                              color: colors.text.secondary,
                            }}
                          >
                            {label}
                          </TableCell>
                        ))}
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {devices.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={5} align="center">
                            {loading
                              ? t("core.devices.loadingDevices")
                              : t("core.devices.noDevices")}
                          </TableCell>
                        </TableRow>
                      ) : (
                        sortDevices(devices, isSelected).map((device) => (
                          <TableRow
                            key={device.mac}
                            hover
                            onClick={() => handleToggle(device.mac)}
                            sx={{ cursor: "pointer" }}
                          >
                            <TableCell padding="checkbox">
                              <Checkbox
                                checked={isSelected(device.mac)}
                                color="secondary"
                              />
                            </TableCell>
                            <TableCell
                              sx={{
                                fontFamily: "monospace",
                                fontSize: "0.85rem",
                              }}
                            >
                              {device.is_manual ? (
                                <Typography variant="caption" color="text.secondary">—</Typography>
                              ) : device.mac}
                            </TableCell>
                            <TableCell
                              sx={{
                                fontFamily: "monospace",
                                fontSize: "0.85rem",
                              }}
                            >
                              <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                {device.ip}
                                {device.is_manual && (
                                  <Chip label={t("core.devices.manual")} size="small" variant="outlined" sx={{ fontSize: "0.7rem", height: 20 }} />
                                )}
                              </Box>
                            </TableCell>
                            <TableCell onClick={(e) => e.stopPropagation()}>
                              {editingMac === device.mac ? (
                                <B4InlineEdit
                                  value={findConfigDevice(device.mac)?.name || device.alias || device.vendor || ""}
                                  onSave={async (name) => {
                                    updateDevice(device.mac, { name });
                                    setEditingMac(null);
                                  }}
                                  onCancel={() => setEditingMac(null)}
                                />
                              ) : (
                                <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                                  {(findConfigDevice(device.mac)?.name || device.alias || device.vendor) ? (
                                    <B4Badge
                                      label={findConfigDevice(device.mac)?.name || device.alias || device.vendor || ""}
                                      color="primary"
                                      variant={isSelected(device.mac) ? "filled" : "outlined"}
                                    />
                                  ) : (
                                    <Typography variant="caption" color="text.secondary">
                                      {t("core.unknown")}
                                    </Typography>
                                  )}
                                  <IconButton
                                    size="small"
                                    onClick={() => setEditingMac(device.mac)}
                                    sx={{ opacity: 0.6, "&:hover": { opacity: 1 } }}
                                  >
                                    <EditIcon sx={{ fontSize: 16 }} />
                                  </IconButton>
                                </Box>
                              )}
                            </TableCell>
                            <TableCell onClick={(e) => e.stopPropagation()}>
                              <TextField
                                size="small"
                                type="number"
                                value={findConfigDevice(device.mac)?.mss_clamp || ""}
                                onChange={(e) => {
                                  const val = e.target.value === "" ? undefined : Number(e.target.value);
                                  updateDevice(device.mac, { mss_clamp: val });
                                }}
                                placeholder="off"
                                slotProps={{
                                  htmlInput: {
                                    min: 10,
                                    max: 1460,
                                    style: { width: 50, padding: "4px 8px" },
                                  },
                                }}
                                sx={{
                                  "& .MuiOutlinedInput-root": {
                                    fontSize: "0.85rem",
                                  },
                                }}
                              />
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Grid>
            ) : (
              <B4Alert severity="warning">
                {t("settings.Devices.arpUnavailable")}
              </B4Alert>
            )}

            <Grid size={{ xs: 12 }}>
              <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
                {t("settings.Devices.manualDevices")}
              </Typography>
              <B4Alert severity="info">
                {t("settings.Devices.manualDevicesDesc")}
              </B4Alert>

              <Box sx={{ display: "flex", gap: 1, alignItems: "center", mt: 2, mb: 1 }}>
                <TextField
                  size="small"
                  label={t("settings.Devices.manualIp")}
                  value={manualIp}
                  onChange={(e) => setManualIp(e.target.value)}
                  placeholder="192.168.1.100"
                  onKeyDown={(e) => { if (e.key === "Enter") handleAddManualDevice(); }}
                  sx={{ minWidth: 160 }}
                />
                <TextField
                  size="small"
                  label={t("settings.Devices.manualName")}
                  value={manualName}
                  onChange={(e) => setManualName(e.target.value)}
                  placeholder={t("settings.Devices.manualNamePlaceholder")}
                  onKeyDown={(e) => { if (e.key === "Enter") handleAddManualDevice(); }}
                  sx={{ minWidth: 160 }}
                />
                <Button
                  variant="outlined"
                  size="small"
                  onClick={handleAddManualDevice}
                  disabled={!manualIp.trim()}
                  startIcon={<AddIcon />}
                >
                  {t("core.add")}
                </Button>
              </Box>

              {manualDevices.length > 0 && (
                <TableContainer
                  component={Paper}
                  sx={{
                    bgcolor: colors.background.paper,
                    border: `1px solid ${colors.border.default}`,
                    maxHeight: 200,
                  }}
                >
                  <Table size="small" stickyHeader>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ bgcolor: colors.background.dark, color: colors.text.secondary }}>
                          {t("core.devices.ip")}
                        </TableCell>
                        <TableCell sx={{ bgcolor: colors.background.dark, color: colors.text.secondary }}>
                          {t("core.devices.deviceName")}
                        </TableCell>
                        <TableCell sx={{ bgcolor: colors.background.dark, width: 50 }} />
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {manualDevices.map((d) => (
                        <TableRow key={d.mac}>
                          <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
                            {d.ip}
                          </TableCell>
                          <TableCell>
                            {d.name ? (
                              <B4Badge label={d.name} color="primary" variant="outlined" />
                            ) : (
                              <Typography variant="caption" color="text.secondary">—</Typography>
                            )}
                          </TableCell>
                          <TableCell>
                            <IconButton
                              size="small"
                              onClick={() => handleRemoveManualDevice(d.mac)}
                              sx={{ color: colors.text.secondary, "&:hover": { color: "error.main" } }}
                            >
                              <DeleteIcon sx={{ fontSize: 18 }} />
                            </IconButton>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </Grid>
          </>
        )}
      </Grid>
    </B4Section>
  );
};
