import base64
import os
from cryptography.fernet import Fernet
from flask import Flask, abort, jsonify, request,render_template
from flask_cors import CORS
import sqlite3 as sq  # 1. sqlite -> sqlite3 yapıldı
from dotenv import load_dotenv
load_dotenv(".env")
# 2. envion -> environ olarak düzeltildi
gizli_imza = os.environ.get("USER_AGENT")
anahtar = os.environ.get("ANAHTAR")
DB_Yolu = os.environ.get("DBPATH","Sifreler.db")

kasa = Fernet(anahtar.encode())


Api = Flask(__name__)
CORS(Api)

@Api.before_request
def engelle():
	if request.path ==  ("/"):
		return
	#imza = request.headers.get("Efenin_imzasi")
	#if (imza != gizli_imza):
		#abort(403)


@Api.route("/", methods=["GET"])
def Anasayfa():
	return render_template("index.html")


@Api.route("/sifre_al", methods=["POST"])
def sifre_al():
    veri = request.get_json()
    sifre = veri.get("sifre")
    kullanici_adi = veri.get("kullanici_adi")
    platform_adi = veri.get("platform_adi")
    
    if not platform_adi or not kullanici_adi or not sifre:
    	return jsonify({"durum":"Eksik alan"}),400

    # 3. base.urlsafe_b64lencode -> base64.urlsafe_b64encode yapıldı
    db_sifre = kasa.encrypt(sifre.encode()).decode()

    conn = sq.connect(DB_Yolu)
    cursor = conn.cursor()
    cursor.execute(
        """ CREATE TABLE IF NOT EXISTS PASSWORDS(
	   id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT NOT NULL,
    kullanici_adi TEXT NOT NULL,
    sifre TEXT NOT NULL
	)"""
    )

    # 4. Soru işaretindeki fazla virgül silindi ve değişkenler (parantez içinde) sorguya bağlandı
    cursor.execute(
        """ INSERT INTO PASSWORDS (platform, kullanici_adi, sifre) VALUES (?, ?, ?)""",
        (platform_adi, kullanici_adi, db_sifre),
    )

    conn.commit()
    conn.close()
    return jsonify({"durum":"kaydedildi"}) 


@Api.route("/sifre_gor", methods=["GET"])
def sifre_gor():
    conn = sq.connect(DB_Yolu)
    cursor = conn.cursor()

    # Tablodaki tüm verileri (id, platform, kullanıcı adı ve şifreli şifre) çekiyoruz
    cursor.execute(""" SELECT id, platform, kullanici_adi, sifre FROM PASSWORDS """)
    all_rows = cursor.fetchall()
    conn.close()

    # JavaScript'e göndereceğimiz temiz liste
    temiz_liste = []

    # Veritabanından gelen her satırı tek tek siber süzgeçten geçiriyoruz
    for satir in all_rows:
        id_no = satir[0]
        platform = satir[1]
        k_adi = satir[2]
        sifreli_sifre = satir[3]  # Veritabanındaki 'gAAAAABm...' hali

        try:
            # İşte sihirli an: Şifreli metni .encode() yapıp kasa ile çözüyoruz ve .decode() ile düz metne çeviriyoruz
            cozulen_sifre = kasa.decrypt(sifreli_sifre.encode()).decode()
        except Exception:
            cozulen_sifre = "Şifre Çözülemedi! (Hatalı Anahtar)"

        # Temizlenen verileri listemize sözlük (dict) formatında ekliyoruz
        temiz_liste.append(
            {
                "id": id_no,
                "platform": platform,
                "kullanici_adi": k_adi,
                "sifre": cozulen_sifre,  # HTML artık burayı kabak gibi net okuyacak!
            }
        )

    # JavaScript'e anlamsız karakterler yerine bu tertemiz listeyi yolluyoruz
    return jsonify(temiz_liste)

    
@Api.route("/sifre_sil",methods=["POST"])
def sifre_sil():
	veri = request.get_json()
	id_no = veri.get("id")
	conn = sq.connect(DB_Yolu)
	cursor = conn.cursor()
	cursor.execute(
    "DELETE FROM PASSWORDS WHERE id=?",
    (id_no,)
)
	conn.commit()
	conn.close()
	return jsonify ({"durum":"silimdi"})
if __name__ == "__main__":
    Api.run(debug=False)
