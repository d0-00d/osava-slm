"""Build the SLM Fine-Tune Playbook as a .docx with real Word styles.

    python3 docs/playbook_docx.py "SLM Fine-Tune Playbook.docx"

The same content is published as a web page (claude.ai artifact "SLM Fine-Tune
Playbook"); edit both together. Needs python-docx (in the .venv).
"""
from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

ACCENT = RGBColor(0x15, 0x5F, 0xAB)
MUTED  = RGBColor(0x5C, 0x65, 0x72)
BAD    = RGBColor(0x9E, 0x3A, 0x2C)
GOOD   = RGBColor(0x2C, 0x6E, 0x4E)
INK2   = RGBColor(0x3C, 0x44, 0x50)

doc = Document()

# ---- base styles
st = doc.styles["Normal"]
st.font.name = "Calibri"; st.font.size = Pt(10.5)
st.paragraph_format.space_after = Pt(7)
st.paragraph_format.line_spacing = 1.15

for name, size, color, before in (
        ("Heading 1", 20, ACCENT, 22), ("Heading 2", 14, ACCENT, 16),
        ("Heading 3", 11.5, INK2, 12)):
    s = doc.styles[name]
    s.font.name = "Calibri"; s.font.size = Pt(size); s.font.bold = True
    s.font.color.rgb = color
    s.paragraph_format.space_before = Pt(before); s.paragraph_format.space_after = Pt(5)

def shade(cell, hex_):
    el = OxmlElement("w:shd"); el.set(qn("w:fill"), hex_)
    cell._tc.get_or_add_tcPr().append(el)

def code(text):
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.left_indent = Inches(0.22); pf.space_before = Pt(4); pf.space_after = Pt(9)
    pf.line_spacing = 1.0
    r = p.add_run(text)
    r.font.name = "Consolas"; r.font.size = Pt(8.8)
    r.font.color.rgb = INK2
    r._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
    return p

def why(label, text, color=ACCENT):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.22)
    p.paragraph_format.space_after = Pt(9)
    r = p.add_run(f"{label}  "); r.bold = True; r.font.size = Pt(9.5); r.font.color.rgb = color
    r2 = p.add_run(text); r2.font.size = Pt(9.5); r2.font.color.rgb = INK2
    return p

def table(headers, rows, widths=None):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Table Grid"; t.alignment = WD_TABLE_ALIGNMENT.LEFT
    for i, h in enumerate(headers):
        c = t.rows[0].cells[i]; c.text = ""
        r = c.paragraphs[0].add_run(h.upper())
        r.bold = True; r.font.size = Pt(7.8); r.font.color.rgb = MUTED
        shade(c, "EEF0F4")
    for row in rows:
        cells = t.add_row().cells
        for i, v in enumerate(row):
            cells[i].text = ""
            p = cells[i].paragraphs[0]; p.paragraph_format.space_after = Pt(2)
            mono = v.startswith("`") and v.endswith("`")
            r = p.add_run(v.strip("`"))
            r.font.size = Pt(9)
            if mono: r.font.name = "Consolas"; r.font.size = Pt(8.6)
    if widths:
        for row in t.rows:
            for i, w in enumerate(widths):
                row.cells[i].width = Inches(w)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return t

# ════════════════════════ title
h = doc.add_paragraph(); h.paragraph_format.space_after = Pt(2)
r = h.add_run("SLM FINE-TUNE PLAYBOOK")
r.font.name = "Calibri"; r.font.size = Pt(26); r.bold = True; r.font.color.rgb = ACCENT

p = doc.add_paragraph(); p.paragraph_format.space_after = Pt(10)
r = p.add_run("A complete procedure for fine-tuning a small language model into a domain "
              "classifier on a single consumer GPU — the data pipeline, the libraries, the "
              "exact hyperparameters, how to serve it, and the eighteen ways this went "
              "wrong without announcing itself.")
r.font.size = Pt(11.5); r.font.color.rgb = INK2

table(["", ""], [
    ["Worked example", "SmolLM3-3B → Windows security telemetry classifier"],
    ["Result", "59.4% → 89.8% bucketed accuracy; threats dismissed 69.6% → 0.0%"],
    ["Hardware", "RTX 4060 Laptop, 8 GB VRAM"],
    ["Serving", "0.22 s per event on a Radeon 780M iGPU; 7 of 7 output checks passed"],
    ["Wall clock", "~4 days to first ship, including labelling"],
    ["Source", "github.com/d0-00d/osava-slm"],
], widths=[1.4, 5.0])

doc.add_heading("What this produces — and what it does not", level=2)
doc.add_paragraph(
    "A specialist that beats a general-purpose SLM by roughly 30 points on its domain, "
    "exports to GGUF, runs in Ollama at 4-bit, and has a measured number attached to the "
    "weights that actually ship rather than to a checkpoint.")
doc.add_paragraph(
    "It will not produce a model that works outside its training distribution. The "
    "specialist answers \"none\" on out-of-domain input rather than declining. That has to "
    "be handled by routing, not by hope.")

# ════════════════════════ environment
doc.add_heading("Environment", level=1)
doc.add_paragraph(
    "Fine-tuning stacks break across minor versions in ways that do not raise errors. "
    "group_by_length vanished from TRL between 0.23 and 0.24; SFTConfig silently skips its "
    "own gradient-accumulation division depending on the model's signature. Freeze the set "
    "that worked.")
table(["Package", "Version", "Role"], [
    ["`python`", "3.12.3", "—"],
    ["`torch`", "2.6.0", "CUDA runtime, bf16 autocast"],
    ["`transformers`", "5.5.0", "model, tokenizer, chat template"],
    ["`peft`", "0.20.0", "LoRA adapters, merge_and_unload"],
    ["`trl`", "0.24.0", "SFTTrainer, completion-only loss"],
    ["`bitsandbytes`", "0.50.2", "NF4 quantisation, paged 8-bit optimiser"],
    ["`datasets`", "4.3.0", "in-memory dataset wrapper"],
    ["`accelerate`", "1.14.0", "device placement"],
    ["`gguf`", "0.19.0", "reading GGUF metadata back"],
    ["`llama.cpp`", "any", "convert_hf_to_gguf.py only — pure Python"],
    ["`llama-server`", "b11177", "serving: raw /completion with token probabilities. Pin a build tag"],
], widths=[1.5, 0.9, 4.0])
why("No compiler needed.",
    "The HF→GGUF converter is a Python script; only llama-quantize is a compiled binary, "
    "and `ollama create --quantize q4_K_M` replaces it. That removes the entire C++ "
    "toolchain from the deployment path.")

PHASES = []

# ════════════════════════ phase 1
def phase(n, eyebrow, title):
    doc.add_page_break() if n in (4, 7) else None
    doc.add_heading(f"{n}.  {title}", level=1)
    p = doc.add_paragraph(); p.paragraph_format.space_after = Pt(8)
    r = p.add_run(eyebrow.upper()); r.font.size = Pt(7.8); r.bold = True; r.font.color.rgb = MUTED

phase(1, "before any data", "Freeze the input contract")
doc.add_paragraph(
    "Decide the exact byte-level format the model will ever see, and write it in one file. "
    "Everything downstream — generation, evaluation, deployment — imports it rather than "
    "restating it.")
code('''# contract.py
FIELD_ORDER = ["EventID", "EventType", "Image", "CommandLine",
               "ParentImage", "ParentCommandLine", "User", "Signed",
               "Signer", "DestinationIp", "DestinationPort",
               "DestinationHostname", "TargetFilename", "LogonType",
               "AuthPackage"]
MAX_CMDLINE  = 512
TRUNC_MARKER = "<truncated>"

# rendered form — the only thing the model ever sees
#   EventID: 1
#   Image: C:\\Windows\\System32\\cmd.exe
#   CommandLine: ...''')
why("Field order is load-bearing.",
    "The model learns positional expectations; reordering at inference is a distribution "
    "shift that produces no error. Truncation is part of the contract too — if training "
    "truncates at 512 and production does not, the model meets sequences it has never seen.")
doc.add_heading("Design the output schema for scoring, not for reading", level=3)
doc.add_paragraph(
    "Put the field you will be graded on first. It can then be scored by length-normalised "
    "log-likelihood over a closed vocabulary without generating anything else — "
    "deterministic, fast, and immune to the model rambling.")
code('''{"severity": "high", "isThreat": true, "threatType": "malware",
 "indicators": {...}, "reasoning": "..."}
       ^ scored by pinning the prefix {"severity": " and comparing
         P("none") / P("low") / P("medium") / P("high")''')

# ════════════════════════ phase 2
phase(2, "corpus", "Collect, then collapse to behaviours")
table(["Stage", "Count", "Tool"], [
    ["Benign capture, one working machine", "52,791", "`evtx_bulk.py`"],
    ["Attack corpus, 199 EVTX files", "2,929", "`evtx_bulk.py`"],
    ["After behaviour-signature grouping", "1,663", "`signature.py`"],
    ["Expanded to events, capped per signature", "1,993", "`build_train.py`"],
], widths=[3.3, 0.9, 1.9])
doc.add_paragraph(
    "A behaviour signature collapses who and where, and keeps what happened. Usernames, "
    "GUIDs, version directories, IPs and ephemeral ports all become placeholders, so 400 "
    "occurrences of svchost -k netsvcs become one decision instead of 400.")
code('''# signature.py — normalisation applied before grouping
GUID -> <GUID>    SID -> <SID>    C:\\Users\\bob -> <PROFILE>
1.2.3.4 -> <IP>   4.18.23110 -> <VER>   base64{40,} -> <B64>
port 49152+ -> "ephemeral"    port 443 -> "wk:443"''')
why("Two payoffs.",
    "Labelling throughput — 1,663 decisions instead of 55,720. And a real disjointness "
    "primitive: train/eval separation enforced on behaviour rather than row id, so the "
    "eval set cannot measure memorisation.")
why("Watch the cardinality.",
    "Leaving ephemeral source ports literal made every network event its own signature. "
    "Bucketing ports took the benign profile from 14,990 signatures to 1,788.")

# ════════════════════════ phase 3
phase(3, "labels", "Machine-propose, human-decide, measure the gap")
code('''python3 prefilter.py        # score + rank: ambient? ubiquitous? technique match?
python3 triage.py --queue triage_queue.jsonl --out labels_auto.json
python3 triage.py --blind --sample 100 --out blind_labels.json
python3 compare_labels.py labels_auto.json blind_labels.json''')
doc.add_paragraph(
    "Rule-based proposals make the volume tractable. Blind passes measure whether the "
    "proposals are any good — the same human labels a random sample with the machine's "
    "opinion hidden, and agreement is computed after.")
why("Sample before you tune, and never reuse the sample.",
    "The first blind pass here read 79% agreement — after rules had been tuned against it. "
    "An uncontaminated second sample read 70%. The first number was measuring the tuning.")
why("Presentation order is a confound.",
    "The triage queue sorts by descending suspicion score, so labelling straight through "
    "yields every unambiguous positive first. Stopping early produces a set that is 100% "
    "one class. Shuffle unless you intend the ordering.")
doc.add_heading("State the class boundary as a rule, not as intuition", level=3)
code('''# boundary.py — one definition, applied to BOTH train and eval
durable state change  -> malicious    # account created, service installed,
                                      # autorun key written, task scheduled
observation only      -> suspicious   # net user, whoami, adfind, reg query
affirmatively normal  -> benign       # named hard negatives''')
why("A boundary applied to one side is worse than none.",
    "Here `net localgroup ... /add` was suspicious in training and malicious in eval; the "
    "model learned one and was graded against the other, and three of its fourteen errors "
    "were not errors at all.")
why("Match the verb, not the path.",
    "A rule keyed on ...\\CurrentVersion\\Run flags `reg query`, which reads the autorun "
    "key. Fifteen rows were nearly mislabelled this way — twice, in two different files.")

# ════════════════════════ phase 4
phase(4, "evaluation set", "Build it before the model exists")
table(["Property", "Value", "Why it matters"], [
    ["Size", "138", "±4.2 points SE; at n=50 it was ±6.9 and nothing under ~14 points was detectable"],
    ["Real vs synthetic", "106 / 32", "synthetic events have no external ground truth — you measure agreement with your own generator"],
    ["Exact signature overlap", "0", "hard assert in build_sft.py"],
    ["Parent-blind action overlap", "0", "the check that actually works"],
    ["Subset tags", "v2-50, expand-100", "so earlier numbers stay comparable when the set grows"],
], widths=[1.6, 1.1, 3.4])
why("The disjointness check you write first will be too weak.",
    "The signature includes the parent process, so a generator choosing parents at random "
    "manufactures distinct-looking duplicates of byte-identical commands. 16 of the "
    "original 50 eval events shared their exact action with training while the assertion "
    "passed. The parent-blind check rejected 12 of 100 new candidates the strict check "
    "waved through.")
why("Never renumber the yardstick.",
    "When the eval set grows, tag the original subset and report both. Otherwise every "
    "previously published number silently refers to a different measurement.")
why("Gold labels are snapshotted into results files.",
    "A run scored before a label correction keeps the label it saw. Predictions do not "
    "change when a gold label does, so refresh stale golds at report time rather than "
    "re-running everything.")

# ════════════════════════ phase 5
phase(5, "targets", "Every output field must be derivable from the input")
code('''python3 targets.py            # inspect indicator frequency + samples
python3 build_sft.py --eval-set eval_set_v3.jsonl''')
doc.add_paragraph(
    "Only the label comes from the labelling pass. Everything else — indicators, threat "
    "type, reasoning — is recomputed from the event text, so the model is never asked to "
    "produce something it cannot observe.")
why("Provenance is not reasoning.",
    "808 of 1,993 rows carried the rationale \"unique to this capture\" — a fact about the "
    "corpus, not the event. Training on it teaches the model to justify itself with "
    "information it will never have at inference, and that string correlates with the label.")
why("Keep the indicator vocabulary closed.",
    "28 entries at first, 45 now. The model can be wrong but cannot fabricate. Check that no single "
    "indicator predicts a class — ours ran 90/94/71% across the three classes, which is "
    "what descriptive rather than diagnostic looks like.")
why("Audit the assembled file, not its inputs.",
    "Capping and merging happen after the component sets are built and can reintroduce a "
    "shortcut none of them had.")
doc.add_heading("Run your output checks on the targets themselves", level=3)
code('''python3 hallucination_check.py --eval-set train_final.jsonl \\
        --responses targets.json    # the targets, scored like model output
  parse / severity / threat_type / key_vocab / grounded / verdict / supported
  # gate: 0 failures on every training row, before any training run''')
doc.add_paragraph(
    "The shipped model gave explanations that argued against its own verdict on 49 of 138 "
    "alerts: \"signed by Microsoft, runs from System32. This matches a known attack "
    "technique.\" It did not invent that habit. The same checks, run over the training "
    "targets, found 661 of 1,180 threat targets with no incriminating indicator, 623 of them "
    "real captures of techniques the extractor had no rule for.")
why("Fix it at the source.",
    "Rules for the missing techniques (UAC bypass, credential access, persistence, defence "
    "evasion, proxy execution), and one honesty key, context_dependent, for threats that no "
    "single field explains. The next model produced 1 unsupported alert instead of 49.")
why("Quote the evidence, not the field.",
    "Targets quoted the first 120 characters of the command line under three or four keys at "
    "once. The model learned to copy, and on a 700-character encoded PowerShell line it wrote "
    "the whole line under every key until it ran out of tokens. Quoting what each rule matched "
    "(-w hidden, FromBase64String, the download URL) removed both parse failures.")
why("A gap in the vocabulary invites invention.",
    "Logons had 26 rows and no keys, and the model made up negotiate_auth. Adding logon keys "
    "and 53 rows stopped the invention. On logon types it had never seen, it then picked a "
    "real key that was wrong (service_logon for a screen unlock): grounded, well formed, and "
    "invisible to every check.")

# ════════════════════════ phase 6
phase(6, "training", "QLoRA on 8 GB")
code("python3 train_qlora.py --out adapters/v3 --epochs 4 --sev-weight 20")
table(["Setting", "Value", "Note"], [
    ["Quantisation", "NF4", "double quant, bf16 compute"],
    ["LoRA rank / alpha / dropout", "16 / 32 / 0.05", ""],
    ["Target modules", "all 7", "q,k,v,o + gate,up,down — MLPs are where a format→label mapping lives"],
    ["Learning rate", "2e-4", "cosine, warmup 3%"],
    ["Batch × accum", "2 × 8", "effective 16"],
    ["Optimiser", "paged_adamw_8bit", "paged survives the 8 GB ceiling"],
    ["max_grad_norm", "0.3", ""],
    ["Gradient checkpointing", "on", "use_reentrant: False"],
    ["Packing", "off", "would cross the prompt/completion boundary"],
    ["completion_only_loss", "on", "the prompt is identical on every row"],
    ["Peak VRAM", "7.9 GB", "of 8.2 — no headroom"],
    ["Throughput", "~15 s/step", "≈50 min for 3 epochs on 1.8k rows"],
], widths=[1.9, 1.2, 3.0])
doc.add_heading("Weight the token you are actually grading", level=3)
doc.add_paragraph(
    "The label was one token out of a 94-token completion — 1.07% of the loss. The other "
    "99% taught JSON punctuation. Token accuracy hit 99.6% while the model was still "
    "coin-flipping the verdict.")
code('''# subclass SFTTrainer; weight the label token in the loss
w = torch.ones_like(tgt, dtype=torch.float32)
pos = valid[i].nonzero()[SEV_OFFSET]           # fixed offset, asserted
if int(tgt[i, pos]) in self.sev_ids:           # never weight blind
    w[i, pos] = self.sev_weight
loss = (ce * w)[valid].sum() / w[valid].sum()  # weighted MEAN''')
why("On a laptop, watch the memory, not the core.",
    "A 2.5-hour run held the GPU core near 78 °C, inside its 87 °C target. The GDDR6 junction "
    "ran at 82–84 °C, and nvidia-smi reports it as N/A on this card. gpu_watchdog.py reads it "
    "from HWiNFO's CSV log and stops the job above 85 °C, or when the log goes quiet, because "
    "a watchdog that cannot see the temperature must not let the job run. Training resumes "
    "from the last checkpoint.")
why("Weight 20 gave the best accuracy; weight 5 recovered the middle class.",
    "20x → 92.0% accuracy and 100% recall on the top class, but the middle class collapsed "
    "to 8 predictions out of 138. 5x → 89.1%, and the middle class came back to 18. Higher "
    "weight rewards confident extremes. Pick by which error you can afford.")

# ════════════════════════ phase 7
phase(7, "selection", "Never select on validation loss")
code('''python3 pick_checkpoint.py --adapter-dir adapters/v3 \\
        --eval-set eval_set_v3.jsonl --out-dir logs/v3''')
doc.add_paragraph("Save every checkpoint, turn load_best_model_at_end off, and choose on "
                  "the task metric.")
table(["Run", "Lowest-loss checkpoint", "Its accuracy", "Best accuracy"], [
    ["v1", "step140", "36.0%", "68.0%"],
    ["v3", "step235", "91.3%", "92.0%"],
    ["v4", "step188", "67.4%", "89.9%"],
], widths=[0.8, 2.0, 1.4, 1.4])
why("Three runs out of three.",
    "In v1 the lowest-loss checkpoint was the single worst model in the sweep. With the "
    "default setting the trainer would have selected it and reported it as \"best\". Loss "
    "measures the whole completion; you care about one token of it.")
why("Load the base once and swap adapters.",
    "Reloading 3B of weights eleven times is most of the sweep's runtime.")
doc.add_heading("Measure the noise floor before believing a difference", level=3)
table(["Final checkpoint", "Clean events correct", "P(correct | malicious)", "What changed"], [
    ["v3", "107 / 122", "0.79", "shipped model"],
    ["v5", "107 / 122", "0.67", "new targets, quarantine, prompt"],
    ["v6", "109 / 122", "0.65", "span quotes, logon rows"],
    ["v6, seed 2", "104 / 122", "0.75", "the random seed, nothing else"],
], widths=[1.3, 1.5, 1.6, 2.0])
doc.add_paragraph(
    "v5 looked six points worse than v3. Most of that gap was measurement. v3's 92% was the "
    "best of ten checkpoints, chosen on the same eval set it was reported on. v5 lost 4 of the "
    "16 eval events whose training near-duplicates the quarantine had rightly removed. On the "
    "122 clean events, the two final checkpoints tie.")
why("Train the same configuration twice.",
    "Two runs that differ only in seed disagreed on 14 of 138 events. No single-run "
    "comparison smaller than that means anything, so compare final checkpoints, split clean "
    "from overlapping events, and report a continuous score (the probability of the correct "
    "class) next to accuracy.")

# ════════════════════════ phase 8
phase(8, "export", "Merge, convert, quantise — re-measure at every step")
code('''python3 merge_export.py --adapter adapters/v3/checkpoint-282 --out dist/sentri-v1
python3 run_eval.py --model dist/sentri-v1 --eval-set eval_set_v3.jsonl    # VERIFY
python3 ~/llama.cpp/convert_hf_to_gguf.py dist/sentri-v1 \\
        --outfile dist/sentri-v1/model-f16.gguf --outtype f16
ollama create mymodel --quantize q4_K_M -f dist/sentri-v1/Modelfile
powershell -File q4_eval.ps1 mymodel                                       # VERIFY AGAIN''')
table(["Artefact", "Accuracy", "Delta"], [
    ["LoRA adapter on NF4 base", "92.0%", "—"],
    ["Merged into bf16", "89.9%", "−2.1 — adapter was trained against a quantised base"],
    ["Quantised to Q4_K_M via Ollama", "89.8%", "−0.1 overall, but 11 individual events flipped"],
], widths=[2.2, 1.0, 3.0])
why("Each conversion is a new model.",
    "Merging a QLoRA adapter into fp16 weights is not lossless — it was trained to correct "
    "a quantised base. Quantising again shifts it further. Here Q4 held the same accuracy "
    "but became systematically more aggressive: zero under-calls, more false alarms. Quote "
    "the number for the weights that ship.")
doc.add_heading("Generate the Modelfile; never hand-write it", level=3)
why("Drift is invisible.",
    "The system prompt must be byte-identical to the one used in training. Generate it from "
    "the same source file, and record a prompt_sha256 so drift is detectable rather than "
    "merely present.")
doc.add_heading("A checksum proves the file, not the model", level=3)
doc.add_paragraph(
    "An untrained SmolLM3 sat in a second Ollama store under a classifier-like name, within "
    "128 bytes of the real model's size. Its checksum was pinned with full confidence, and it "
    "answered \"none\" on a PsExec service binary.")
code('''# contract.json: events the trained model gets right and the base model gets wrong
"canaries": [{"id": "M011", "expect": "malicious"},   # PsExec: base says none
             {"id": "X074", "expect": "malicious"},   # COM hijack
             {"id": "B025", "expect": "benign"}]      # catches flag-everything''')
why("Run the canaries at every start, and classify nothing until they pass.",
    "Choose them per model: M011 was a canary for v3 at 0.995 and scored 0.36 in v6, because "
    "the quarantine removed its training twins. A good canary is an event every seed gets "
    "right with a wide margin.")

# ════════════════════════ phase 9
phase(9, "integration", "Export the contract as data; route by input type")
code("python3 export_contract.py --also ../app/src/contract.json")
doc.add_paragraph(
    "The contract is authored in Python and consumed by the application. Emit it as JSON — "
    "field order, label scale, bucketing, routing rule, indicator vocabulary, prompt hash — "
    "and have the app read that file rather than restate it.")
why("Four facts had been restated on the app side, and all four had drifted.",
    "The worst: the app required a `confidence` field the new schema no longer emitted, so "
    "every response failed validation and fell back to \"benign\". The model was perfect and "
    "the integration discarded all of it. Nothing logged an error.")
why("A specialist is narrower than the slot it replaces.",
    "The app accepted nine input types; the model was trained on one. On the other eight it "
    "does not decline — it answers \"none\". A reverse shell submitted as a code snippet came "
    "back clean. The contract must name its supported inputs, and anything else routes "
    "elsewhere.")
why("Fail open.",
    "When output is unparseable — 1 in 138 here, on a malicious event — escalate. A fallback "
    "of \"clean\" is indistinguishable from a confident verdict.")
why("A port is a second implementation. Test it on real data.",
    "The app's TypeScript copy of the event converter and target rules matches the Python on "
    "5,267 real records and 12,423 explanation cases. Each mismatch on the way there was a "
    "language difference, never a logic bug: Python counts code points, splits on a wider "
    "whitespace set, lets . match \\r, and treats œ as a word character, so \\b disagreed on "
    "one mojibake command line. Lookups keyed by process names use own properties, so a "
    "binary named constructor cannot reach Object.prototype.")

phase(10, "serving", "Serve the decision, compute the explanation")
doc.add_paragraph(
    "Phase 5 made every output field except the label a function of the event and the label. "
    "So at serving time, ask the model for the label alone: prefill the answer up to the "
    "severity, run one forward pass, and read the severity from the probabilities of the next "
    "token. The host computes indicators, threat type and reasoning with the same rules that "
    "built the training targets.")
code('''POST /completion
{ "prompt": template(body) + '{"severity": "',
  "n_predict": 1, "n_probs": 10, "temperature": 0, "cache_prompt": true }
# P(none) P(low) P(medium) P(high) -> class probabilities, margin, review flag''')
table(["138 held-out events, Radeon 780M", "Generating", "Severity only"], [
    ["Accuracy", "124 / 138", "124 / 138"],
    ["Same severity on every event", "—", "138 / 138"],
    ["Time per event", "6.6 s", "0.22 s"],
    ["Startup with canaries", "25 s", "5.4 s"],
    ["Output checks passed", "5 of 7", "7 of 7"],
], widths=[2.8, 1.5, 1.5])
why("The model spent 300 tokens imitating code.",
    "Those tokens were where it invented keys, quoted text that was not in the event, and "
    "explained alerts with reassuring evidence. Computed on the host, the explanation quotes "
    "only what is in the event, by construction, and an output guard is no longer needed. The "
    "price is that an explanation can say only what the rules detect, which is what the model "
    "was trained to say anyway.")

# ════════════════════════ failure catalogue
doc.add_page_break()
doc.add_heading("Failure catalogue: eighteen bugs that raised no error", level=1)
doc.add_paragraph(
    "Every one of these produced a running, plausible-looking system. They are listed "
    "because each cost hours to find and minutes to fix, and none would have been caught by "
    "tests of the code.")

TRAPS = [
 ("PROMPT", "The prompt was defined twice and differed by one full stop",
  "Two variants named round2 and strict differed by a trailing period, so every A/B "
  "compared a prompt against itself and reported the difference as a real effect.",
  "One module owns the prompt; training, evaluation and deployment all import it."),
 ("PROMPT", "The chat template injected today's date",
  "SmolLM3's template prepends \"Today Date: ...\" from strftime_now() and "
  "\"Reasoning Mode: /think\". Baselines were not reproducible across midnight, and the "
  "model was asked to reason in the position the harness pinned the answer.",
  "Use the template's own /system_override escape. Inspect the rendered prompt, not the "
  "message you passed in."),
 ("PROMPT", "The same bug returned through the GGUF",
  "The GGUF embeds the chat template, and Ollama renders SYSTEM through it — so the "
  "deployed model got the date header back. Every production inference ran on a prompt the "
  "model was never trained on.",
  "Render the deployed prompt and diff it against the training prompt. Assume nothing about "
  "who does the templating."),
 ("LOSS", "The weighted loss ran at an 8x learning rate",
  "HF skips its /gradient_accumulation_steps division when the model accepts loss kwargs and "
  "num_items_in_batch is passed, expecting a token sum. A custom loss returning a mean "
  "therefore trains at accum-times the intended rate.",
  "Compare train_loss against eval_loss on the first steps. An exact factor-of-accum gap is "
  "the tell."),
 ("EVAL", "Disjointness passed on a technicality",
  "Signatures include the parent process, so random parent selection manufactured "
  "distinct-looking duplicates. 16 of 50 eval events shared their action with training.",
  "Check the action with identity fields removed, not just the full signature."),
 ("EVAL", "Results files carried stale gold labels",
  "Every run scored before a label correction kept the label it saw, so old runs were graded "
  "against an obsolete answer key.",
  "Refresh gold from the current eval set at report time; predictions are unaffected by "
  "label changes."),
 ("LABELS", "A path-matching rule flagged reads as writes",
  "reg query ...\\CurrentVersion\\Run reads the autorun key. A rule matching the path called "
  "it persistence. This happened twice, in two files, months apart.",
  "Rules match the verb. Print every row a rule would change and read them before applying."),
 ("LABELS", "Train and eval used different class boundaries",
  "The same command was suspicious in training and malicious in evaluation. The model "
  "learned one and was graded against the other.",
  "One boundary module applied to both sets in the same run, asserting zero contradictions "
  "afterwards."),
 ("SELECTION", "Loss-based checkpoint selection picked the worst model",
  "Three runs out of three. In one, the lowest-loss checkpoint scored 36% where the best "
  "scored 68%.",
  "load_best_model_at_end=False, keep every checkpoint, select on the task metric."),
 ("INTEGRATION", "A required field the new schema no longer emitted",
  "The app threw when confidence was absent, retried, threw again, and returned a \"benign\" "
  "fallback. Every event came back clean with no error logged.",
  "Generate the contract as data and have both sides read it. Fallbacks escalate; they never "
  "assert \"clean\"."),
 ("INTEGRATION", "Few-shot examples taught the schema the fine-tune replaced",
  "The app's prompt builder showed two examples of the old seven-field output. A zero-shot "
  "fine-tune shown a contradictory schema will emit the contradictory schema.",
  "A fine-tune gets the format it was trained on and no examples. Keep the few-shot path for "
  "generalist models only."),
 ("TARGETS", "Explanations argued against their own verdicts",
  "49 of 138 alerts were explained only by exculpatory evidence. The training targets did it: "
  "661 of 1,180 threat targets had nothing incriminating to cite.",
  "Run the output checks over the targets, add rules for the missing techniques, and let a "
  "target say that no single field is conclusive."),
 ("TARGETS", "The model copied a command line until it ran out of tokens",
  "Targets repeated a 120-character prefix under several keys. On a 700-character encoded "
  "command, the model wrote the full line under each key and never closed the JSON.",
  "Quote the span each rule matched. Never repeat a long value under two keys."),
 ("TARGETS", "Grounded, well formed, and wrong",
  "On logon types absent from training, the model chose a real indicator key with a value "
  "copied from the event, but the wrong key. No output check can catch that.",
  "Compute the explanation on the host (phase 10). Where the model must generate it, cover "
  "every value of the field in training."),
 ("DEPLOY", "The checksum pinned an untrained model",
  "A base SmolLM3 of nearly identical size sat under a classifier-like name. Identified by "
  "architecture and size, its hash was pinned as the model's.",
  "Canary events at every start. The file's hash says which file; only behaviour says which "
  "model."),
 ("CONTRACT", "The exported threat-type list was ['_']",
  "The prompt moved its list behind a <THREAT_TYPES> placeholder, and the exporter's regex "
  "now matched the placeholder. The app's guard would have reset every threat type the model "
  "gave.",
  "The exporter asserts that every exported value appears in the prompt as the model reads "
  "it."),
 ("PORT", "One mojibake command line split the two languages",
  "Python's \\b is Unicode-aware and JavaScript's is ASCII. In ntdsutil â€œifm, Python saw no "
  "word boundary before ifm and JavaScript did, so one side reported credential access.",
  "Compile the port's patterns with Python's meaning of \\b \\w \\d \\s, and run parity on "
  "real telemetry, not only on the curated sets."),
 ("SELECTION", "A regression that was noise",
  "A new model looked six points worse. The old number was a best-of-ten checkpoint picked on "
  "the eval set, and a seed change alone moved 14 of 138 events.",
  "Compare final checkpoints, split clean from overlapping events, and measure seed variance "
  "before attributing a difference."),
]
for i, (tag, title, desc, fix) in enumerate(TRAPS, 1):
    p = doc.add_paragraph(); p.paragraph_format.space_before = Pt(11); p.paragraph_format.space_after = Pt(2)
    r = p.add_run(f"{i}.  "); r.bold = True; r.font.size = Pt(10.5); r.font.color.rgb = MUTED
    r = p.add_run(f"[{tag}]  "); r.bold = True; r.font.size = Pt(8); r.font.color.rgb = BAD
    r = p.add_run(title); r.bold = True; r.font.size = Pt(10.5)
    p = doc.add_paragraph(); p.paragraph_format.left_indent = Inches(0.28); p.paragraph_format.space_after = Pt(3)
    r = p.add_run(desc); r.font.size = Pt(9.5); r.font.color.rgb = MUTED
    p = doc.add_paragraph(); p.paragraph_format.left_indent = Inches(0.28); p.paragraph_format.space_after = Pt(2)
    r = p.add_run("Fix:  "); r.bold = True; r.font.size = Pt(9.5); r.font.color.rgb = GOOD
    r = p.add_run(fix); r.font.size = Pt(9.5); r.font.color.rgb = INK2

# ════════════════════════ checklist
doc.add_page_break()
doc.add_heading("The procedure, in short", level=1)
for i, step in enumerate([
    "Freeze the input contract and the output schema. Put the graded field first.",
    "Collect a corpus for each class. Collapse it to behaviour signatures.",
    "Machine-propose labels; blind-label an uncontaminated sample; measure agreement.",
    "State the class boundary as a rule and apply it to training and evaluation in the same run.",
    "Build the eval set before the model exists. Assert disjointness on behaviour and on "
    "identity-stripped action. Size it so your expected effect exceeds the standard error.",
    "Derive every target field except the label from the input.",
    "Audit the assembled training file for single-token shortcuts and one-sided classes.",
    "Train with completion-only loss. Weight the graded token. Verify the mask lands where "
    "you think it does.",
    "Keep every checkpoint. Select on the task metric, never on loss.",
    "Merge, convert, quantise — and re-measure after each, because each is a different model.",
    "Export the contract as data. Route unsupported inputs away. Fail open.",
    "Run the output checks over the training targets. Zero failures before any run.",
    "Train the same configuration twice before believing any difference between runs.",
    "Prove the loaded model with canaries at every start, chosen for that model.",
    "Serve the graded field alone. Compute the rest on the host with the code that built the "
    "targets, parity-tested on real data.",
], 1):
    p = doc.add_paragraph(); p.paragraph_format.left_indent = Inches(0.3)
    p.paragraph_format.first_line_indent = Inches(-0.3); p.paragraph_format.space_after = Pt(6)
    r = p.add_run(f"{i:>2}.  "); r.font.name = "Consolas"; r.font.size = Pt(9.5); r.font.color.rgb = MUTED
    r = p.add_run(step); r.font.size = Pt(10.5)

p = doc.add_paragraph(); p.paragraph_format.space_before = Pt(14)
p.paragraph_format.left_indent = Inches(0.22)
r = p.add_run("The recurring theme across all eighteen failures: nothing crashed. ")
r.bold = True; r.font.size = Pt(10); r.font.color.rgb = ACCENT
r = p.add_run("Every bug produced a working system with plausible numbers. The defence is not "
              "more tests — it is measuring the thing you actually care about, end to end, on "
              "the artefact you actually ship.")
r.font.size = Pt(10); r.font.color.rgb = INK2

import sys
doc.save(sys.argv[1])
print("saved", sys.argv[1])