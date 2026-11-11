pragma circom 2.0.0;

// One IVC step: z_out = z_in^3 + z_in + secret.
// `step_in` / `step_out` carry the public IVC state; `secret` is a private
// per-step input that the proof does not reveal.
template Step() {
    signal input step_in[1];
    signal input secret;
    signal output step_out[1];
    signal sq;
    sq <== step_in[0] * step_in[0];
    step_out[0] <== sq * step_in[0] + step_in[0] + secret;
}

component main {public [step_in]} = Step();
