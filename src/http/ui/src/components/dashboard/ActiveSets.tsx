import { colors } from "@design";
import { B4SetConfig } from "@models/config";
import {
  Circle as CircleIcon,
  FolderOpen as FolderIcon,
} from "@mui/icons-material";
import { Box, Chip, Stack, Typography } from "@mui/material";
import { useNavigate } from "react-router";
import { useTranslation } from "react-i18next";

interface ActiveSetsProps {
  sets: B4SetConfig[];
}

export const ActiveSets = ({ sets }: ActiveSetsProps) => {
  const navigate = useNavigate();
  const { t } = useTranslation();

  if (sets.length === 0) return null;

  return (
    <Box
      sx={{
        mb: 1.5,
        p: 1.5,
        borderRadius: 1,
        bgcolor: colors.background.paper,
        border: `1px solid ${colors.border.default}`,
      }}
    >
      <Typography
        variant="caption"
        sx={{
          color: colors.text.secondary,
          textTransform: "uppercase",
          letterSpacing: "0.5px",
          mb: 1.5,
          display: "block",
        }}
      >
        {t("dashboard.activeSets.title")}
      </Typography>
      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
        {sets.map((set) => {
          const domainCount =
            (set.targets.sni_domains?.length || 0) +
            (set.targets.geosite_categories?.length || 0);
          const ipCount =
            (set.targets.ip?.length || 0) +
            (set.targets.geoip_categories?.length || 0);
          const totalTargets = domainCount + ipCount;

          return (
            <Chip
              key={set.id}
              icon={
                set.enabled ?
                  <CircleIcon sx={{ fontSize: "8px !important" }} />
                : <FolderIcon sx={{ fontSize: "14px !important" }} />
              }
              label={`${set.name}: ${totalTargets} ${t("dashboard.activeSets.targets")}`}
              size="small"
              onClick={() => { navigate(`/sets/${set.id}`)?.catch(() => {}); }}
              sx={{
                bgcolor:
                  set.enabled ?
                    `${colors.secondary}15`
                  : `${colors.text.disabled}10`,
                color: set.enabled ? colors.text.primary : colors.text.disabled,
                borderColor:
                  set.enabled ?
                    `${colors.secondary}40`
                  : `${colors.text.disabled}20`,
                cursor: "pointer",
                fontWeight: 500,
                "& .MuiChip-icon": {
                  color: set.enabled ? "#4caf50" : colors.text.disabled,
                },
                "&:hover": {
                  bgcolor:
                    set.enabled ?
                      `${colors.secondary}25`
                    : `${colors.text.disabled}20`,
                },
              }}
              variant="outlined"
            />
          );
        })}
      </Stack>
    </Box>
  );
};
