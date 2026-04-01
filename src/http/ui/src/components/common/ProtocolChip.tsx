import { Stack } from "@mui/material";
import { TcpIcon, UdpIcon, BlockIcon, ProxyIcon, DuplicateIcon } from "@b4.icons";
import { B4Badge } from "@b4.elements";

interface ProtocolChipProps {
  protocol: "TCP" | "UDP";
  flags?: string;
}

export const ProtocolChip = ({ protocol, flags }: ProtocolChipProps) => {
  const icon = protocol === "TCP" ? <TcpIcon /> : <UdpIcon />;
  const isBlocked = flags?.startsWith("ipblock");
  const isSocks5 = flags === "socks5";
  const isDuplicate = flags === "tcp-dup";

  return (
    <Stack direction="row" spacing={0.5} alignItems="center">
      <B4Badge
        icon={icon}
        label={protocol}
        variant="outlined"
        color={protocol === "TCP" ? "primary" : "secondary"}
      />
      {isSocks5 && (
        <B4Badge
          icon={<ProxyIcon />}
          label="proxy"
          title="SOCKS5 Proxy"
          variant="outlined"
          color="info"
        />
      )}
      {isDuplicate && (
        <B4Badge
          icon={<DuplicateIcon />}
          label="dup"
          title="Duplicated packet"
          variant="outlined"
          color="secondary"
        />
      )}
      {isBlocked && (
        <B4Badge
          icon={<BlockIcon />}
          label="ip"
          title="Blocked by IP"
          variant={flags === "ipblock-cached" ? "outlined" : "filled"}
          color="error"
        />
      )}
    </Stack>
  );
};
