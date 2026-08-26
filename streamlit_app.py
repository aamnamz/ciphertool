import streamlit as st
import importlib.util
from pathlib import Path

# ---------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------
st.set_page_config(
    page_title="CipherLab",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------------
# LOAD CIPHER CORE
# ---------------------------------------------------------
spec = importlib.util.spec_from_file_location(
    "cipher_core",
    Path(__file__).with_name("cipher_core.py")
)

core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)

# ---------------------------------------------------------
# CIPHER LIBRARY
# ---------------------------------------------------------
CIPHERS = {
    "Additive Cipher": (
        "additive_encrypt",
        "additive_decrypt",
        "Integer shift",
        "Substitution"
    ),

    "Multiplicative Cipher": (
        "multiplicative_encrypt",
        "multiplicative_decrypt",
        "Integer key, coprime with 26",
        "Substitution"
    ),

    "Affine Cipher": (
        "affine_encrypt",
        "affine_decrypt",
        "a and b keys; a must be coprime with 26",
        "Substitution"
    ),

    "Monoalphabetic Substitution": (
        "monoalphabetic_encrypt",
        "monoalphabetic_decrypt",
        "26 unique letters",
        "Substitution"
    ),

    "Autokey Cipher": (
        "autokey_encrypt",
        "autokey_decrypt",
        "Letter key",
        "Polyalphabetic"
    ),

    "Vigenère Cipher": (
        "vigenere_encrypt",
        "vigenere_decrypt",
        "Letter key",
        "Polyalphabetic"
    ),

    "Playfair Cipher": (
        "playfair_encrypt",
        "playfair_decrypt",
        "Letter key",
        "Digraph"
    ),

    "Keyless Transposition": (
        "keyless_transposition_encrypt",
        "keyless_transposition_decrypt",
        "No key",
        "Transposition"
    ),

    "Keyed Transposition": (
        "keyed_transposition_encrypt",
        "keyed_transposition_decrypt",
        "Keyword",
        "Transposition"
    ),

    "Double Transposition": (
        "double_transposition_encrypt",
        "double_transposition_decrypt",
        "Two keywords",
        "Transposition"
    ),
}

# ---------------------------------------------------------
# CUSTOM CSS
# ---------------------------------------------------------
st.markdown("""
<style>

.block-container {
    max-width: 1400px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

/* Hero */
.hero {
    padding: 2.2rem 2.5rem;
    border-radius: 24px;
    border: 1px solid rgba(128,128,128,.20);
    background:
        radial-gradient(circle at top right,
            rgba(120,90,220,.18),
            transparent 40%),
        radial-gradient(circle at bottom left,
            rgba(30,180,160,.12),
            transparent 40%),
        linear-gradient(
            135deg,
            rgba(100,80,150,.10),
            rgba(40,170,150,.08)
        );
    margin-bottom: 1.5rem;
}

.hero h1 {
    font-size: 3.2rem;
    font-weight: 800;
    margin: 0;
    letter-spacing: -1px;
}

.hero p {
    font-size: 1.05rem;
    opacity: .75;
    margin-top: .5rem;
}

/* Section headings */
.section-title {
    font-size: 1.35rem;
    font-weight: 700;
    margin-top: 1rem;
    margin-bottom: .8rem;
}

/* Cipher cards */
.cipher-card {
    padding: 1rem 1.1rem;
    border-radius: 16px;
    border: 1px solid rgba(128,128,128,.20);
    background: rgba(128,128,128,.045);
    min-height: 105px;
    margin-bottom: .8rem;
}

.cipher-card:hover {
    border-color: rgba(120,100,220,.45);
    background: rgba(120,100,220,.06);
}

.cipher-name {
    font-weight: 700;
    font-size: .98rem;
}

.cipher-category {
    font-size: .72rem;
    opacity: .65;
    margin-top: .2rem;
}

/* Selected pipeline */
.pipeline {
    display: flex;
    align-items: center;
    gap: .5rem;
    flex-wrap: wrap;
    padding: 1rem 1.2rem;
    border-radius: 16px;
    border: 1px solid rgba(120,100,220,.25);
    background: rgba(120,100,220,.06);
    margin: 1rem 0 1.5rem 0;
}

.pipeline-item {
    padding: .45rem .8rem;
    border-radius: 10px;
    background: rgba(120,100,220,.15);
    font-size: .85rem;
    font-weight: 600;
}

.pipeline-arrow {
    opacity: .5;
    font-size: 1.1rem;
}

/* Config card */
.config-card {
    border: 1px solid rgba(128,128,128,.20);
    border-radius: 18px;
    padding: 1.2rem;
    margin-bottom: 1rem;
    background: rgba(128,128,128,.035);
}

/* Result */
.result-card {
    border: 1px solid rgba(60,180,140,.30);
    border-radius: 18px;
    padding: 1.2rem;
    background: rgba(60,180,140,.055);
}

.step-card {
    border-left: 3px solid rgba(120,100,220,.65);
    padding: .6rem 1rem;
    margin: .5rem 0;
    background: rgba(128,128,128,.04);
    border-radius: 0 10px 10px 0;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    border-right: 1px solid rgba(128,128,128,.15);
}

</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# HERO
# ---------------------------------------------------------
st.markdown("""
<div class="hero">
    <h1>🔐 CipherLab</h1>
    <p>
        Interactive classical cryptography laboratory —
        build and experiment with multi-cipher encryption pipelines.
    </p>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------
with st.sidebar:

    st.markdown("## ⚙️ Configuration")

    operation = st.radio(
        "Operation",
        ["Encrypt", "Decrypt"],
        horizontal=True
    )

    st.divider()

    st.markdown("### 📚 Cipher selection")
    st.caption("Select one or more ciphers to create a pipeline.")

    # Select all / clear
    col1, col2 = st.columns(2)

    with col1:
        select_all = st.button(
            "Select all",
            use_container_width=True
        )

    with col2:
        clear_all = st.button(
            "Clear",
            use_container_width=True
        )

# ---------------------------------------------------------
# SESSION STATE
# ---------------------------------------------------------
if "selected_ciphers" not in st.session_state:
    st.session_state.selected_ciphers = [
        "Vigenère Cipher"
    ]

if select_all:
    st.session_state.selected_ciphers = list(CIPHERS.keys())

if clear_all:
    st.session_state.selected_ciphers = []

# ---------------------------------------------------------
# CIPHER CHECKBOX GRID
# ---------------------------------------------------------
st.markdown(
    '<div class="section-title">🔑 Choose your ciphers</div>',
    unsafe_allow_html=True
)

cipher_names = list(CIPHERS.keys())

cols = st.columns(3)

for i, name in enumerate(cipher_names):

    with cols[i % 3]:

        enc, dec, key_hint, category = CIPHERS[name]

        checked = st.checkbox(
            name,
            value=name in st.session_state.selected_ciphers,
            key=f"cipher_checkbox_{name}"
        )

        if checked and name not in st.session_state.selected_ciphers:
            st.session_state.selected_ciphers.append(name)

        elif not checked and name in st.session_state.selected_ciphers:
            st.session_state.selected_ciphers.remove(name)

        st.markdown(
            f"""
            <div class="cipher-card">
                <div class="cipher-name">{name}</div>
                <div class="cipher-category">
                    {category} · {key_hint}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

# ---------------------------------------------------------
# SELECTED PIPELINE
# ---------------------------------------------------------
selected = st.session_state.selected_ciphers

st.markdown(
    '<div class="section-title">🧩 Cipher pipeline</div>',
    unsafe_allow_html=True
)

if selected:

    pipeline_html = '<div class="pipeline">'

    for i, cipher in enumerate(selected):

        pipeline_html += (
            f'<div class="pipeline-item">{i + 1}. {cipher}</div>'
        )

        if i < len(selected) - 1:
            pipeline_html += (
                '<div class="pipeline-arrow">→</div>'
            )

    pipeline_html += "</div>"

    st.markdown(
        pipeline_html,
        unsafe_allow_html=True
    )

    st.caption(
        f"{len(selected)} cipher"
        f"{'s' if len(selected) != 1 else ''} selected. "
        "Ciphers are applied in the order shown above."
    )

else:

    st.info(
        "Select at least one cipher to build your encryption pipeline."
    )

# ---------------------------------------------------------
# INPUT
# ---------------------------------------------------------
st.markdown(
    '<div class="section-title">📝 Input</div>',
    unsafe_allow_html=True
)

text = st.text_area(
    "Input text",
    value="HELLO WORLD" if operation == "Encrypt" else "",
    height=180,
    placeholder=(
        "Enter plaintext..."
        if operation == "Encrypt"
        else "Enter ciphertext..."
    ),
    label_visibility="collapsed"
)

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------
values = {}

if selected:

    st.markdown(
        '<div class="section-title">🔧 Cipher configuration</div>',
        unsafe_allow_html=True
    )

    for index, name in enumerate(selected):

        enc, dec, key_hint, category = CIPHERS[name]

        st.markdown(
            f"""
            <div class="config-card">
                <strong>{index + 1}. {name}</strong>
                <br>
                <small>{category} · {key_hint}</small>
            </div>
            """,
            unsafe_allow_html=True
        )

        # -------------------------------
        # ADDITIVE / MULTIPLICATIVE
        # -------------------------------
        if name in [
            "Additive Cipher",
            "Multiplicative Cipher"
        ]:

            values[name] = {}

            values[name]["key"] = st.number_input(
                f"{name} — Key",
                value=3,
                step=1,
                key=f"key_{name}"
            )

            if (
                name == "Multiplicative Cipher"
                and core.mod_inverse(
                    int(values[name]["key"]),
                    26
                ) is None
            ):
                st.warning(
                    "For decryption, the multiplicative key "
                    "needs an inverse modulo 26."
                )

        # -------------------------------
        # AFFINE
        # -------------------------------
        elif name == "Affine Cipher":

            values[name] = {}

            c1, c2 = st.columns(2)

            with c1:

                values[name]["a"] = st.number_input(
                    "a",
                    value=5,
                    step=1,
                    key="affine_a"
                )

            with c2:

                values[name]["b"] = st.number_input(
                    "b",
                    value=8,
                    step=1,
                    key="affine_b"
                )

            if core.mod_inverse(
                int(values[name]["a"]),
                26
            ) is None:

                st.warning(
                    "a must be relatively prime to 26."
                )

        # -------------------------------
        # MONOALPHABETIC
        # -------------------------------
        elif name == "Monoalphabetic Substitution":

            values[name] = {}

            values[name]["key"] = st.text_input(
                "26-letter substitution alphabet",
                "QWERTYUIOPASDFGHJKLZXCVBNM",
                key="mono_key"
            ).upper()

        # -------------------------------
        # POLYALPHABETIC / PLAYFAIR
        # -------------------------------
        elif name in [
            "Autokey Cipher",
            "Vigenère Cipher",
            "Playfair Cipher"
        ]:

            values[name] = {}

            values[name]["key"] = st.text_input(
                f"{name} — Key",
                "KEY",
                key=f"key_{name}"
            ).upper()

        # -------------------------------
        # KEYLESS
        # -------------------------------
        elif name == "Keyless Transposition":

            values[name] = {}

            st.caption(
                "No key required for this cipher."
            )

        # -------------------------------
        # KEYED TRANSPOSITION
        # -------------------------------
        elif name == "Keyed Transposition":

            values[name] = {}

            values[name]["key"] = st.text_input(
                "Keyword",
                "SECRET",
                key="keyed_transposition_key"
            ).upper()

        # -------------------------------
        # DOUBLE TRANSPOSITION
        # -------------------------------
        elif name == "Double Transposition":

            values[name] = {}

            c1, c2 = st.columns(2)

            with c1:

                values[name]["key1"] = st.text_input(
                    "First key",
                    "FIRST",
                    key="double_key1"
                ).upper()

            with c2:

                values[name]["key2"] = st.text_input(
                    "Second key",
                    "SECOND",
                    key="double_key2"
                ).upper()

# ---------------------------------------------------------
# RUN PIPELINE
# ---------------------------------------------------------
st.divider()

run = st.button(
    "⚡ Run Cipher Pipeline",
    type="primary",
    use_container_width=True,
    disabled=not selected
)

if run:

    if not text.strip():

        st.warning("Please enter some text first.")

    else:

        try:

            current_text = text
            steps = []

            # ---------------------------------------------
            # APPLY EACH CIPHER
            # ---------------------------------------------

            # Encryption → selected order
            # Decryption → reverse order
            pipeline = (
                selected
                if operation == "Encrypt"
                else list(reversed(selected))
                )
            for index, name in enumerate(pipeline):
                
                enc, dec, key_hint, category = CIPHERS[name]

                fn = getattr(
                    core,
                    enc if operation == "Encrypt" else dec
                )

                # -----------------------------------------
                # ADDITIVE / MULTIPLICATIVE
                # -----------------------------------------
                if name in [
                    "Additive Cipher",
                    "Multiplicative Cipher"
                ]:

                    key = int(
                        values[name]["key"]
                    )

                    result = fn(
                        current_text,
                        key
                    )

                # -----------------------------------------
                # AFFINE
                # -----------------------------------------
                elif name == "Affine Cipher":

                    a = int(
                        values[name]["a"]
                    )

                    b = int(
                        values[name]["b"]
                    )

                    result = fn(
                        current_text,
                        a,
                        b
                    )

                # -----------------------------------------
                # MONOALPHABETIC
                # -----------------------------------------
                elif name == "Monoalphabetic Substitution":

                    key = values[name]["key"]

                    if (
                        len(key) != 26
                        or len(set(key)) != 26
                        or not key.isalpha()
                    ):

                        raise ValueError(
                            "Substitution key must contain "
                            "exactly 26 unique letters."
                        )

                    result = fn(
                        current_text,
                        key
                    )

                # -----------------------------------------
                # AUTOKEY / VIGENERE / PLAYFAIR
                # -----------------------------------------
                elif name in [
                    "Autokey Cipher",
                    "Vigenère Cipher",
                    "Playfair Cipher"
                ]:

                    key = values[name]["key"]

                    if not key:

                        raise ValueError(
                            f"{name}: key cannot be empty."
                        )

                    result = fn(
                        current_text,
                        key
                    )

                # -----------------------------------------
                # KEYLESS
                # -----------------------------------------
                elif name == "Keyless Transposition":

                    result = fn(
                        current_text
                    )

                # -----------------------------------------
                # KEYED TRANSPOSITION
                # -----------------------------------------
                elif name == "Keyed Transposition":

                    key = values[name]["key"]

                    if not key:

                        raise ValueError(
                            "Keyed Transposition: "
                            "key cannot be empty."
                        )

                    result = fn(
                        current_text,
                        key
                    )

                # -----------------------------------------
                # DOUBLE TRANSPOSITION
                # -----------------------------------------
                elif name == "Double Transposition":

                    key1 = values[name]["key1"]
                    key2 = values[name]["key2"]

                    if not key1 or not key2:

                        raise ValueError(
                            "Double Transposition: "
                            "both keys are required."
                        )

                    result = fn(
                        current_text,
                        key1,
                        key2
                    )

                else:

                    raise ValueError(
                        f"Unsupported cipher: {name}"
                    )

                steps.append(
                    {
                        "cipher": name,
                        "input": current_text,
                        "output": str(result)
                    }
                )

                current_text = str(result)

            # -------------------------------------------------
            # RESULTS
            # -------------------------------------------------
            st.markdown(
                '<div class="section-title">✨ Results</div>',
                unsafe_allow_html=True
            )

            st.markdown(
                '<div class="result-card">',
                unsafe_allow_html=True
            )

            st.subheader("Final Result")

            st.code(
                current_text,
                language="text"
            )

            st.markdown(
                "</div>",
                unsafe_allow_html=True
            )

            # -------------------------------------------------
            # PIPELINE BREAKDOWN
            # -------------------------------------------------
            st.markdown(
                '<div class="section-title">🔍 Pipeline breakdown</div>',
                unsafe_allow_html=True
            )

            for i, step in enumerate(steps):

                st.markdown(
                    f"""
                    <div class="step-card">
                        <strong>
                            Step {i + 1} — {step["cipher"]}
                        </strong>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                with st.expander(
                    f"View {step['cipher']} transformation"
                ):

                    st.text_area(
                        "Input",
                        step["input"],
                        height=100,
                        key=f"step_input_{i}"
                    )

                    st.text_area(
                        "Output",
                        step["output"],
                        height=100,
                        key=f"step_output_{i}"
                    )

            # -------------------------------------------------
            # DOWNLOAD
            # -------------------------------------------------
            st.download_button(
                "⬇️ Download final result",
                current_text,
                "cipher_result.txt",
                "text/plain",
                use_container_width=True
            )

        except Exception as e:

            st.error(
                f"Cipher pipeline failed: {str(e)}"
            )

# ---------------------------------------------------------
# CIPHER LIBRARY
# ---------------------------------------------------------
st.divider()

st.markdown(
    '<div class="section-title">📚 Cipher library</div>',
    unsafe_allow_html=True
)

cols = st.columns(3)

for i, (cipher, data) in enumerate(CIPHERS.items()):

    with cols[i % 3]:

        st.markdown(
            f"""
            <div class="cipher-card">
                <div class="cipher-name">
                    {cipher}
                </div>

                <div class="cipher-category">
                    {data[3]} · {data[2]}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )