import streamlit as st
import enc_dec as e_d
import tempfile
import os

st.title("Encrypt iT")

#Basic side bar consisting of all the pages
with st.sidebar:
    st.title('Encrypt iT')
    page=st.radio('Go To', ["Encrypt","Decrypt"])


if page=='Encrypt':
    file=st.file_uploader('Upload file: ')
    if file is not None:
        st.write(f"✅ File uploaded: **{file.name}**")

    if st.button("Encrypt File!"):
        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
            temp_input.write(file.read())
            temp_input_path = temp_input.name

        encrypted_path = temp_input_path + ".enc"

        pw = e_d.generate_password()
        e_d.encrypt_file(temp_input_path, encrypted_path, pw)

        with open(encrypted_path, "rb") as f:
            st.download_button(
                label="⬇️ Download Encrypted File",
                data=f,
                file_name=file.name + ".enc",
                mime="application/octet-stream"
            )

        # Step 5: Show password
        st.success("🔐 Encryption complete!")
        st.code(pw, language="text")

        # Step 6: Cleanup temporary input (optional)
        os.remove(temp_input_path)

if page=='Decrypt':
    st.title('Decryption')
    file=st.file_uploader('Upload file: ')
    if file is not None:
        st.write(f"✅ File uploaded: **{file.name}**")

    pw=st.text_input('passowrd:',type='password')
    if st.button("Decrypt File!"):
        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
            temp_input.write(file.read())
            temp_input_path = temp_input.name

        decrypted_path = temp_input_path+'.enc'
        
        try:
            e_d.decrypt_file(temp_input_path, decrypted_path, pw)
            with open(decrypted_path, "rb") as f:
                st.download_button(
                    label="⬇️ Download Decrypted File",
                    data=f,
                    file_name=(file.name).replace('enc',''),
                    mime="application/octet-stream"
                )

            # Step 5: Show password
            st.success("🔐 Decryption complete!")
        except:
            st.warning('Invalid Password')
        os.remove(temp_input_path)

