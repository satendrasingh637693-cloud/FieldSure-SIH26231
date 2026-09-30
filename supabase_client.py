from functools import lru_cache

import streamlit as st
from supabase import Client, create_client


@lru_cache(maxsize=1)
def get_supabase() -> Client | None:
    url = st.secrets.get("SUPABASE_URL")
    key = st.secrets.get("SUPABASE_SECRET_KEY")

    if not url or not key:
        return None

    return create_client(url, key)


def supabase_enabled() -> bool:
    return get_supabase() is not None