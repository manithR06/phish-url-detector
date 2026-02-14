import streamlit as st
from detector.analyzer import analyze_url

st.set_page_config(page_title="Phishing URL Detector", page_icon="🛡️", layout="centered")

st.title("🛡️ Phishing URL Detection Tool (Rule-Based)")
st.write("Enter a URL to evaluate suspicious patterns using cybersecurity heuristics + regex.")

url = st.text_input("URL", placeholder="example.com/login?redirect=http://evil.com")

col1, col2 = st.columns([1, 1])
with col1:
    run = st.button("Analyze", use_container_width=True)
with col2:
    st.button("Clear", use_container_width=True, on_click=lambda: st.session_state.clear())

if run and url.strip():
    result = analyze_url(url)

    # Display score nicely
    st.subheader("Result")
    st.metric("Risk Level", result["level"], f"{result['score']}/100")

    st.progress(result["score"] / 100)

    st.write("**Domain:**", result["domain"])
    st.write("**Normalized URL:**", result["normalized"])

    st.subheader("Reasons")
    if result["reasons"]:
        for r in result["reasons"]:
            st.warning(r)
    else:
        st.success("No suspicious patterns matched.")

    # Export result
    st.download_button(
        "Download Report (TXT)",
        data="\n".join([
            f"Input: {result['input']}",
            f"Normalized: {result['normalized']}",
            f"Domain: {result['domain']}",
            f"Score: {result['score']}/100",
            f"Level: {result['level']}",
            "Reasons:",
            *[f"- {x}" for x in result["reasons"]]
        ]),
        file_name="phishing_url_report.txt"
    )

elif run:
    st.error("Please enter a URL.")
