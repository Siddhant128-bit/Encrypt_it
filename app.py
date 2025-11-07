import streamlit as st

st.title("Encrypt iT")

#Basic side bar consisting of all the pages
with st.sidebar:
    st.title('Encrypt iT')
    page=st.radio('Go To', ["Encrypt","Decrypt"])


if page=='Encrypt':
    st.title('Encryption')


if page=='Decrypt':
    st.title('Decryption')
