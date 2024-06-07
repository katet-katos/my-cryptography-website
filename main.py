from flask import render_template, Flask, request
from Codes.simmetry import caesar, caesar_dec, encrypt_aes, generate_key, decrypt_aes, encrypt_des, decrypt_des, encrypt_blowfish, decrypt_blowfish, encrypt_chacha20, decrypt_chacha20
from Codes.asimmetry import Points, Points_des, diffie_hellman, diffie_hellman_des, RSA, RSA_des, ElGamal, ElGamal_des, ECDSA, ECDSA_des
from Codes.hesh import MD5, SHA1, SHA224, SHA256, SHA384
from Codes.eds import RSA_key


app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'

@app.route('/')
def start():
    return render_template('base.html')

@app.route('/AES', methods =["GET", "POST"])
def get_AES():
    if request.method == "POST":
        message = request.form['message']
        key = request.form['key']
        dec_message = request.form['dec_message']
        key_priv = key
        key = generate_key(int(key))
        crypt = encrypt_aes(key, message)
        des_crypt = ''
        if dec_message != '':
            des_crypt = decrypt_aes(key,crypt)
            return render_template('onekey.html', title="AES", crypt=dec_message, key=key_priv, message=message, des_crypt=des_crypt, dec_message=dec_message) 
        else:
            return render_template('onekey.html', title="AES", crypt=crypt, key=key_priv, message=message) 
    else:
        return render_template('onekey.html', title="AES") 


@app.route('/DES', methods =["GET", "POST"]) 
def get_DES():
    if request.method == "POST":
        message, key, dec_message = request.form['message'], request.form['key'], request.form['dec_message']
        key_priv = key
        key = bytes(key, 'utf-8')
        crypt = encrypt_des(key, message)
        des_crypt = ''
        if dec_message != '':
            des_crypt = decrypt_des(key,crypt)
            return render_template('onekey.html', title="DES", crypt=dec_message, key=key_priv, message=message, des_crypt=des_crypt, dec_message=dec_message) 
        else:
            return render_template('onekey.html', title="DES", crypt=str(crypt)[2:-1], key=key_priv, message=message) 
    else:
        return render_template('onekey.html', title="DES") 

@app.route('/Blowfish', methods =["GET", "POST"]) 
def get_Blowfish():
    if request.method == "POST":
        message, key, dec_message = request.form['message'], request.form['key'], request.form['dec_message']
        key_priv = key
        key = bytes(key, 'utf-8')
        crypt = encrypt_blowfish(key, message)
        des_crypt = ''
        if dec_message != '':
            des_crypt = decrypt_blowfish(key,crypt)
            return render_template('onekey.html', title="Blowfish", crypt=dec_message, key=key_priv, message=message, des_crypt=des_crypt, dec_message=dec_message) 
        else:
            return render_template('onekey.html', title="Blowfish", crypt=str(crypt)[2:-1], key=key_priv, message=message) 
    else:
        return render_template('onekey.html', title="Blowfish") 

@app.route('/Chacha20', methods =["GET", "POST"]) 
def get_Chacha20():
    if request.method == "POST":
        message, key, dec_message = request.form['message'], request.form['key'], request.form['dec_message']
        key_priv = key
        key = bytes(key, 'utf-8')
        messages = bytes(message, 'utf-8')
        dec_messages = bytes(dec_message, 'utf-8')
        crypt = encrypt_chacha20(key, messages)
        des_crypt = ''
        if dec_message != '':
            des_crypt = decrypt_chacha20(key,crypt)
            return render_template('onekey.html', title="Chacha20", crypt=dec_message, key=key_priv, message=message, des_crypt=str(des_crypt)[2:-1], dec_message=dec_message) 
        else:
            return render_template('onekey.html', title="Chacha20", crypt=str(crypt)[2:-1], key=key_priv, message=message) 
    else:
        return render_template('onekey.html', title="Chacha20") 

@app.route('/caesar', methods =["GET", "POST"])
def get_caesar():
    if request.method == "POST":
        message = request.form['message']
        key = request.form['key']
        cryt = caesar(message, int(key))
        dec_message = request.form["dec_message"]
        decrypt = caesar_dec(dec_message, int(key))
        return render_template('onekey.html', title="Шифр Цезаря", crypt=cryt, message=message, key=key, dec_message=dec_message, des_crypt=decrypt)
    else:
        return render_template('onekey.html', title="Шифр Цезаря")

#Ассимметрия 

@app.route('/Diffie_Hellman', methods =["GET", "POST"])
def get_diffie_hellman():
    if request.method == "POST":
        message = request.form['message']
        key = int(request.form['key'])
        keys = int(request.form['keys'])
        m_public, m_private = 151, 157
        cryt = diffie_hellman(message, key, keys, m_public, m_private)
        dec_message = request.form["dec_message"]
        des_crypt = diffie_hellman_des(dec_message,  key, keys, m_public, m_private)
        return render_template('twokey.html', title="Diffie_Hellman", message=message, key=key,
                               keys=keys, m_public=m_public, crypt=cryt, des_crypt=des_crypt, dec_message=dec_message)
    else:
        return render_template('twokey.html', title="Diffie_Hellman")



@app.route('/RSA', methods =["GET", "POST"])
def get_RSA():
    if request.method == "POST":
        message = int(request.form['message'])
        p_public = int(request.form['a_key'])
        q_public = int(request.form['b_key'])
        e_public = int(request.form['c_key'])
        cryt, d, n = RSA(message, p_public, q_public, e_public)
        cry_message = request.form["dec_message"]
        if cry_message != '':
            decrypt = RSA_des(int(cry_message), d, n,  p_public, q_public, e_public)
        else:
            decrypt = ''
        return render_template('threekey.html', title="RSA", message=message, a_key=p_public, dec_message=cry_message,
                               b_key=q_public, c_key=e_public, crypt=cryt, des_crypt=decrypt)
    return render_template('threekey.html', title="RSA")
    

@app.route('/ElGamal', methods =["GET", "POST"])
def get_ElGamal():
    if request.method == "POST":
        message = request.form['message']
        q_public = int(request.form['key'])
        g_public = int(request.form['keys'])
        cryt, p, key, q = ElGamal(message, q_public, g_public)
        cry_message = request.form["dec_message"]
        decrypt = ElGamal_des(cryt, p, key, q)
        if cry_message == '':
            decrypt = ''
        return render_template('twokey.html', title="ElGamal", message=message, key=q_public,
                               keys=g_public, dec_message=cry_message, crypt=cryt, des_crypt=decrypt)
    return render_template('twokey.html', title="ElGamal")

@app.route('/ECDSA', methods =["GET", "POST"])
def get_ECDSA():
    if request.method == "POST":
        message = int(request.form['message'])
        public_key = int(request.form['key'])
        cryt, k, k_inverse, public_key, n, private_key = ECDSA(public_key, message)
        cry_message = request.form["dec_message"]
        if cry_message != '':
            decrypt = ECDSA_des(cryt, k, k_inverse, public_key, n)
            cryt = ''
            return render_template('simmetry.html', title="ECDSA", message=message, key=public_key, private_key=private_key,
                                dec_message=cry_message, crypt=cryt, des_crypt=decrypt)
        return render_template('simmetry.html', title="ECDSA", message=message, key=public_key, private_key=private_key,
                                dec_message=cry_message, crypt=cryt)
    return render_template('simmetry.html', title="ECDSA")


@app.route('/Points', methods =["GET", "POST"])
def get_Points():
    if request.method == "POST":
        message = request.form['message']
        text = message.split(', ')
        messages = (int(text[0]), int(text[1]))
        p_public = int(request.form['a_key'])
        q_public = int(request.form['b_key'])
        e_public = int(request.form['c_key'])
        cryt = Points(messages, p_public, q_public, e_public)
        cry_message = request.form["dec_message"]
        if cry_message != '':
            decrypt = Points_des(cryt, p_public, q_public, e_public)
        else:
            decrypt = ''
        return render_template('threekey.html', title="Points", message=message, a_key=p_public, dec_message=cry_message,
                               b_key=q_public, c_key=e_public, crypt=cryt, des_crypt=decrypt)
    return render_template('threekey.html', title="Points")


#Хеширование


@app.route('/SHA384', methods =["GET", "POST"])
def get_sha256():
    if request.method == "POST":
        mesege = request.form['message']
        cryt = SHA256(mesege)
        return render_template('hesh.html', title="sha256", crypt=cryt, message=mesege)
    else:
        return render_template('hesh.html', title="sha256")


@app.route('/MD5', methods =["GET", "POST"])
def get_md5():
    if request.method == "POST":
        mesege = request.form['message']
        cryt = MD5(mesege)
        return render_template('hesh.html', title="md5", crypt=cryt, message=mesege)
    else:
        return render_template('hesh.html', title="md5")


@app.route('/SHA1', methods =["GET", "POST"])
def get_sha1():
    if request.method == "POST":
        mesege = request.form['message']
        cryt = SHA1(mesege)
        return render_template('hesh.html', title="sha1", crypt=cryt, message=mesege)
    else:
        return render_template('hesh.html', title="sha1")


@app.route('/SHA224', methods =["GET", "POST"])
def get_sha224():
    if request.method == "POST":
        mesege = request.form['message']
        cryt = SHA224(mesege)
        return render_template('hesh.html', title="sha224", crypt=cryt, message=mesege)
    else:
        return render_template('hesh.html', title="sha224")


@app.route('/SHA256', methods =["GET", "POST"])
def get_sha384():
    if request.method == "POST":
        mesege = request.form['message']
        cryt = SHA384(mesege)
        return render_template('hesh.html', title="sha384", crypt=cryt, message=mesege)
    else:
        return render_template('hesh.html', title="sha384")



#ЭЦП

@app.route('/eds', methods =["GET", "POST"])
def get_eds():
    if request.method == "POST":
        key = int(request.form['key'])
        message = request.form['message']
        cryt, text = RSA_key(message, key)
        return render_template('eds.html', title="ЭЦП методом RSA", crypt=str(cryt)[2:-1], message=message, key=key, text=text)
    else:
        return render_template('eds.html', title="ЭЦП методом RSA")


if __name__ == '__main__':
    app.run(port=8080, host='127.0.0.1')