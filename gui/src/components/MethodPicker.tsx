import { BYPASS_METHODS } from "../types";

const DESCRIPTIONS: Record<string, string> = {
  auto: "Automatic: try the best method per connection.",
  wrong_seq: "Wrong sequence number injection.",
  wrong_seq_ttl: "Wrong sequence + reduced TTL.",
  split_seq: "Split sequence segments.",
  fragmented: "Fragmented ClientHello.",
  padding: "TLS padding extension.",
  delayed_retry: "Delayed retry handshake.",
  double_sni: "Double SNI extension.",
  hostfakesplit: "Host header fake split.",
  fakedsplit: "Fake split segments.",
};

export default function MethodPicker({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div>
      <select
        className="input"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {BYPASS_METHODS.map((m) => (
          <option key={m} value={m}>
            {m}
          </option>
        ))}
      </select>
      {value in DESCRIPTIONS && (
        <p className="mt-1 text-xs text-muted">{DESCRIPTIONS[value]}</p>
      )}
    </div>
  );
}
