import streamlit as st
import pandas as pd
import json
import altair as alt

st.set_page_config(
    page_title="Sentinel Rule Viewer",
    page_icon="🛡",
    layout="wide",
)

st.markdown("""
<style>
    .block-container { padding-top: 1.5rem; padding-bottom: 1rem; }
    h1 { font-size: 1.6rem !important; margin-bottom: 0 !important; }
    h2 { font-size: 1.1rem !important; margin-top: 0.5rem !important; color: #888; font-weight: 400 !important; }
    [data-testid="stMetric"] {
        background: #1e1e2e;
        border: 1px solid #2e2e3e;
        border-radius: 8px;
        padding: 0.6rem 1rem;
    }
    [data-testid="stMetricLabel"] { font-size: 0.75rem !important; color: #aaa !important; }
    [data-testid="stMetricValue"] { font-size: 1.5rem !important; }
    .stTabs [data-baseweb="tab-list"] { gap: 4px; }
    .stTabs [data-baseweb="tab"] { padding: 6px 18px; border-radius: 6px 6px 0 0; }
</style>
""", unsafe_allow_html=True)

st.title("🛡 Sentinel Rule Viewer")

upload_file = st.file_uploader("Upload a Sentinel JSON export", type=["json"], label_visibility="collapsed")

if upload_file is None:
    st.markdown("#### Upload a Sentinel rule export JSON file to get started.")
    st.stop()

file_contents = upload_file.read()
json_data = json.loads(file_contents)
df = pd.json_normalize(json_data['resources'], sep='_')

# ── Derived data ────────────────────────────────────────────────────────────
severity_order = ["High", "Medium", "Low", "Informational"]
severity_colors = {"High": "#d9534f", "Medium": "#f0ad4e", "Low": "#5bc0de", "Informational": "#888888"}

severity_counts = df['properties_severity'].value_counts().reset_index()
severity_counts.columns = ["Severity", "Count"]
severity_counts["Severity"] = pd.Categorical(severity_counts["Severity"], categories=severity_order, ordered=True)
severity_counts = severity_counts.sort_values("Severity")

total = len(df)
enabled = int(df['properties_enabled'].sum()) if 'properties_enabled' in df.columns else None
disabled = (total - enabled) if enabled is not None else None
high = int(severity_counts[severity_counts["Severity"] == "High"]["Count"].sum())

col_map = {
    "properties_displayName": "Name",
    "properties_severity": "Severity",
    "kind": "Type",
    "properties_enabled": "Enabled",
    "properties_tactics": "Tactics",
    "properties_lastModifiedUtc": "Last Modified",
}
available_cols = {k: v for k, v in col_map.items() if k in df.columns}
rules_df = df[list(available_cols.keys())].rename(columns=available_cols).copy()
if "Tactics" in rules_df.columns:
    rules_df["Tactics"] = rules_df["Tactics"].apply(lambda x: ", ".join(x) if isinstance(x, list) else "")
if "Enabled" in rules_df.columns:
    rules_df["Enabled"] = rules_df["Enabled"].map({True: "Yes", False: "No"})

# ── Top metrics ──────────────────────────────────────────────────────────────
m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Total Rules", total)
if enabled is not None:
    m2.metric("Enabled", enabled)
    m3.metric("Disabled", disabled)
m4.metric("High Severity", high)
m5.metric("File", upload_file.name)

st.divider()

# ── Tabs ─────────────────────────────────────────────────────────────────────
tab_overview, tab_rules = st.tabs(["Overview", "Rules"])

# ── Overview tab ─────────────────────────────────────────────────────────────
with tab_overview:
    chart_left, chart_right = st.columns(2)

    with chart_left:
        st.markdown("**Severity**")
        severity_chart = alt.Chart(severity_counts).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4).encode(
            x=alt.X("Severity:N", sort=severity_order, axis=alt.Axis(labelAngle=0, title=None)),
            y=alt.Y("Count:Q", axis=alt.Axis(title=None)),
            color=alt.Color(
                "Severity:N",
                scale=alt.Scale(domain=list(severity_colors.keys()), range=list(severity_colors.values())),
                legend=None,
            ),
            tooltip=["Severity", "Count"],
        ).properties(height=220)
        st.altair_chart(severity_chart, use_container_width=True)

    with chart_right:
        if 'kind' in df.columns:
            st.markdown("**Rule Type**")
            kind_counts = df['kind'].value_counts().reset_index()
            kind_counts.columns = ["Type", "Count"]
            kind_chart = alt.Chart(kind_counts).mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4).encode(
                x=alt.X("Count:Q", axis=alt.Axis(title=None)),
                y=alt.Y("Type:N", sort="-x", axis=alt.Axis(title=None)),
                color=alt.Color("Type:N", legend=None),
                tooltip=["Type", "Count"],
            ).properties(height=220)
            st.altair_chart(kind_chart, use_container_width=True)

    if 'properties_tactics' in df.columns:
        tactics_series = df['properties_tactics'].dropna()
        all_tactics = [t for tactics in tactics_series for t in (tactics if isinstance(tactics, list) else [])]
        if all_tactics:
            st.markdown("**MITRE ATT&CK Tactics**")
            tactics_counts = pd.Series(all_tactics).value_counts().reset_index()
            tactics_counts.columns = ["Tactic", "Count"]
            tactics_chart = alt.Chart(tactics_counts).mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4).encode(
                x=alt.X("Count:Q", axis=alt.Axis(title=None)),
                y=alt.Y("Tactic:N", sort="-x", axis=alt.Axis(title=None)),
                color=alt.Color("Tactic:N", legend=None),
                tooltip=["Tactic", "Count"],
            ).properties(height=max(180, len(tactics_counts) * 28))
            st.altair_chart(tactics_chart, use_container_width=True)

# ── Rules tab ─────────────────────────────────────────────────────────────────
with tab_rules:
    # Filters row
    fc1, fc2, fc3, fc4 = st.columns([2, 1, 1, 1])
    search = fc1.text_input("Search by name", placeholder="Search...", label_visibility="collapsed")
    active_filters = {}
    for col, field in zip([fc2, fc3, fc4], ["Severity", "Type", "Enabled"]):
        if field in rules_df.columns:
            options = sorted(rules_df[field].dropna().unique().tolist())
            selected = col.multiselect(field, options, placeholder=field, label_visibility="collapsed")
            if selected:
                active_filters[field] = selected

    filtered_df = rules_df.copy()
    for field, values in active_filters.items():
        filtered_df = filtered_df[filtered_df[field].isin(values)]
    if search:
        filtered_df = filtered_df[filtered_df["Name"].str.contains(search, case=False, na=False)]

    st.caption(f"{len(filtered_df)} of {total} rules")
    st.dataframe(filtered_df, use_container_width=True, hide_index=True, height=350)

    # Rule detail
    if "Name" in rules_df.columns and "properties_query" in df.columns:
        st.divider()
        rule_names = filtered_df["Name"].dropna().tolist()
        selected_rule = st.selectbox("Inspect rule", ["— select a rule —"] + rule_names, label_visibility="collapsed")
        if selected_rule and selected_rule != "— select a rule —":
            row = df[df["properties_displayName"] == selected_rule].iloc[0]
            d1, d2 = st.columns(2)
            for i, (raw_col, label) in enumerate(available_cols.items()):
                val = row.get(raw_col, "")
                if isinstance(val, list):
                    val = ", ".join(val)
                (d1 if i % 2 == 0 else d2).markdown(f"**{label}:** {val}")
            if pd.notna(row.get("properties_description")):
                st.markdown(f"**Description:** {row['properties_description']}")
            st.markdown("**Query:**")
            st.code(row.get("properties_query", ""), language="sql")
