import { Grid } from "@mui/material";
import {
  Shield as ShieldIcon,
  Lan as LanIcon,
  Storage as StorageIcon,
  BlockOutlined as BlockIcon,
} from "@mui/icons-material";
import { StatCard } from "./StatCard";
import { formatNumber } from "@utils";
import { colors } from "@design";
import { useTranslation } from "react-i18next";
import type { Metrics } from "./Page";

interface MetricsCardsProps {
  metrics: Metrics;
}

export const MetricsCards = ({ metrics }: MetricsCardsProps) => {
  const { t } = useTranslation();
  const targetRate =
    metrics.total_connections > 0
      ? ((metrics.targeted_connections / metrics.total_connections) * 100).toFixed(1)
      : "0.0";

  return (
    <Grid container spacing={2}>
      <Grid size={{ xs: 12, sm: 6, md: 3 }} sx={{ display: "flex" }}>
        <StatCard
          title={t("dashboard.metrics.connections")}
          value={formatNumber(metrics.total_connections)}
          subtitle={`${metrics.current_cps.toFixed(1)} ${t("dashboard.metrics.connPerSec")}`}
          icon={<LanIcon />}
          color={colors.primary}
          variant="outlined"
        />
      </Grid>

      <Grid size={{ xs: 12, sm: 6, md: 3 }} sx={{ display: "flex" }}>
        <StatCard
          title={t("dashboard.metrics.bypassed")}
          value={formatNumber(metrics.targeted_connections)}
          subtitle={`${targetRate}% ${t("dashboard.metrics.ofTotal")}`}
          icon={<ShieldIcon />}
          color={colors.secondary}
          variant="outlined"
        />
      </Grid>

      <Grid size={{ xs: 12, sm: 6, md: 3 }} sx={{ display: "flex" }}>
        <StatCard
          title={t("dashboard.metrics.rstDropped")}
          value={formatNumber(metrics.rst_dropped)}
          icon={<BlockIcon />}
          color={colors.tertiary}
          variant="outlined"
        />
      </Grid>

      <Grid size={{ xs: 12, sm: 6, md: 3 }} sx={{ display: "flex" }}>
        <StatCard
          title={t("dashboard.metrics.packets")}
          value={formatNumber(metrics.packets_processed)}
          subtitle={`${metrics.current_pps.toFixed(1)} ${t("dashboard.metrics.pktPerSec")}`}
          icon={<StorageIcon />}
          color={colors.quaternary}
          variant="outlined"
        />
      </Grid>
    </Grid>
  );
};
