import requests
from bs4 import BeautifulSoup
import re
import base64
import json
import time
import urllib3
from Crypto.Cipher import AES
from urllib.parse import urljoin

# --- Configuración ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BASE_URL = "https://pelisplushd.bz"
PELIS_URL_TEMPLATE = BASE_URL + "/peliculas?page={}"  # Template para la URL con página
HEADERS = {"User-Agent": "Mozilla/5.0"}
SECRET_KEY = "Ak7qrvvH4WKYxV2OgaeHAEg2a5eh16vE"
session = requests.Session()
session.headers.update(HEADERS)

# --- AES helper ---
def decrypt_link(encrypted_b64: str, secret_key: str) -> str:
    data = base64.b64decode(encrypted_b64)
    iv = data[:16]
    ciphertext = data[16:]
    key = secret_key.encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    decrypted = decrypted[:-pad_len]
    return decrypted.decode("utf-8")

# --- Scrap funciones ---
def obtener_peliculas_pagina(num_pagina):
    print(f"🔍 Obteniendo lista de películas de la página {num_pagina}...")
    url = PELIS_URL_TEMPLATE.format(num_pagina)
    r = session.get(url, verify=False)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    peliculas = []
    for a in soup.select("a.Posters-link"):
        titulo = (a.get("data-title") or a.get("title") or a.text.strip()).replace("VER ", "").strip()
        enlace = a.get("href")
        if enlace and not enlace.startswith("http"):
            enlace = urljoin(BASE_URL, enlace)
        peliculas.append({"titulo": titulo, "url": enlace})
    print(f"  → Encontradas {len(peliculas)} películas en la página {num_pagina}.")
    return peliculas

def obtener_peliculas(num_paginas):
    todas_peliculas = []
    for pagina in range(1, num_paginas + 1):
        peliculas_pagina = obtener_peliculas_pagina(pagina)
        todas_peliculas.extend(peliculas_pagina)
        time.sleep(1)  # Pequeña pausa entre páginas para no sobrecargar
    return todas_peliculas

def obtener_iframe_pelicula(html: str):
    soup = BeautifulSoup(html, "html.parser")
    iframe = soup.find("iframe")
    if iframe:
        src = iframe.get("src")
        if src and not src.startswith("http"):
            src = urljoin(BASE_URL, src)
        return src
    return None

def extraer_dataLink(html: str):
    scripts = re.findall(r"const\s+dataLink\s*=\s*(\[.*?\]);", html, re.S)
    if not scripts:
        return []
    data = json.loads(scripts[0])
    resultados = []
    for entry in data:
        idioma = entry.get("video_language")
        for embed in entry.get("sortedEmbeds", []):
            servidor = embed.get("servername")
            tipo = embed.get("type")
            link_cifrado = embed.get("link")
            try:
                url = decrypt_link(link_cifrado, SECRET_KEY)
            except Exception as e:
                url = f"[ERROR al descifrar: {e}]"
            resultados.append({
                "idioma": idioma,
                "servidor": servidor,
                "tipo": tipo,
                "url": url
            })
    return resultados

def extraer_detalles_pelicula(html: str):
    """
    Extrae poster, año, país, género, sinopsis, otros títulos de la ficha
    """
    soup = BeautifulSoup(html, "html.parser")
    detalles = {}
    
    # Extraer título
    h1 = soup.select_one("h1.m-b-5")
    if h1:
        detalles["titulo"] = h1.get_text(strip=True)
    
    # Extraer año del título
    if "titulo" in detalles:
        match = re.search(r'\((\d{4})\)', detalles["titulo"])
        if match:
            detalles["anio"] = match.group(1)
    
    # Poster principal - mejorado
    # Método 1: Buscar en el div con clase col-sm-3
    poster_img = soup.select_one(".col-sm-3 img.img-fluid")
    if poster_img:
        poster_url = poster_img.get("src")
        if poster_url:
            # Asegurarse de que la URL sea absoluta
            if not poster_url.startswith("http"):
                poster_url = urljoin(BASE_URL, poster_url)
            detalles["poster"] = poster_url
    
    # Método 2: Si no se encontró, buscar en las meta etiquetas
    if "poster" not in detalles:
        meta_image = soup.select_one("meta[property='og:image']")
        if meta_image:
            detalles["poster"] = meta_image.get("content")
    
    # Método 3: Último recurso, buscar cualquier imagen en el área principal
    if "poster" not in detalles:
        any_img = soup.select_one(".card img")
        if any_img:
            poster_url = any_img.get("src")
            if poster_url and not poster_url.startswith("http"):
                poster_url = urljoin(BASE_URL, poster_url)
            detalles["poster"] = poster_url
    
    # Sinopsis - corregido para asegurar que siempre se extraiga
    # Método 1: Buscar el párrafo con "Sinopsis:" y luego el div con clase text-large
    sinopsis_container = soup.find("p", string=re.compile(r"Sinopsis:"))
    if sinopsis_container:
        sinopsis_div = sinopsis_container.find_next_sibling("div", class_="text-large")
        if sinopsis_div:
            detalles["sinopsis"] = sinopsis_div.get_text(strip=True)
    
    # Método 2: Si no se encontró, buscar directamente el primer div con clase text-large
    if "sinopsis" not in detalles:
        sinopsis_div = soup.select_one(".text-large")
        if sinopsis_div:
            detalles["sinopsis"] = sinopsis_div.get_text(strip=True)
    
    # País - puede haber múltiples países
    pais_div = soup.find("div", class_="sectionDetail", string=re.compile(r"Pais:"))
    if pais_div:
        paises = []
        pais_links = pais_div.find_all("a")
        for link in pais_links:
            paises.append(link.get_text(strip=True))
        detalles["pais"] = ", ".join(paises)
    
    # Fecha de estreno
    fecha_div = soup.find("div", class_="sectionDetail", string=re.compile(r"Fecha de estreno:"))
    if fecha_div:
        fecha_text = fecha_div.get_text(strip=True)
        match = re.search(r"Fecha de estreno:\s*(\d{4}-\d{2}-\d{2})", fecha_text)
        if match:
            detalles["fecha_estreno"] = match.group(1)
    
    # Otros títulos - corregido para identificar específicamente el div de otros títulos
    otros_titulos_container = soup.find("p", string=re.compile(r"Otros Titulos:"))
    if otros_titulos_container:
        otros_titulos_div = otros_titulos_container.find_next_sibling("div", class_="text-large")
        if otros_titulos_div:
            # Limpiar el texto para eliminar espacios extra y saltos de línea
            titulos_text = otros_titulos_div.get_text(strip=True)
            # Dividir por saltos de línea y limpiar cada título
            titulos = [titulo.strip() for titulo in titulos_text.split('\n') if titulo.strip()]
            detalles["otros_titulos"] = titulos
    
    # Géneros - corregido para extraer múltiples géneros
    generos_container = soup.find("div", class_="p-v-20 p-h-15 text-center")
    if generos_container:
        generos = []
        genero_links = generos_container.find_all("a", title=re.compile(r"Películas del Genero:"))
        for link in genero_links:
            generos.append(link.get_text(strip=True))
        if generos:
            detalles["genero"] = generos
    
    # Año (alternativa si no se encontró en el título)
    if "anio" not in detalles:
        anio_span = soup.select_one("span.font-size-18.text-info.text-semibold")
        if anio_span and anio_span.get_text(strip=True).isdigit():
            detalles["anio"] = anio_span.get_text(strip=True)
    
    return detalles

def procesar_pelicula(pelicula):
    print(f"🎬 Procesando: {pelicula['titulo']}")
    try:
        r = session.get(pelicula["url"], verify=False)
        r.raise_for_status()
        
        # Extraer detalles de la ficha
        detalles = extraer_detalles_pelicula(r.text)
        pelicula.update(detalles)
        
        # Obtener iframe
        iframe_url = obtener_iframe_pelicula(r.text)
        if not iframe_url:
            print("  ❌ No se encontró iframe en la página de la película.")
            pelicula["reproductores"] = []
            return pelicula
        
        # Extraer enlaces reales desde embed69
        r_iframe = session.get(iframe_url, verify=False)
        r_iframe.raise_for_status()
        reproductores = extraer_dataLink(r_iframe.text)
        pelicula["reproductores"] = reproductores
    except Exception as e:
        print(f"  ❌ Error: {e}")
        pelicula["reproductores"] = []
    return pelicula

def guardar_en_json(data, archivo="peliculas_con_reproductores.json"):
    with open(archivo, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"✅ Guardado en {archivo}")

# --- Main ---
def main(num_paginas=1):
    print(f"🚀 Iniciando scraping de {num_paginas} página(s)...")
    peliculas = obtener_peliculas(num_paginas)
    print(f"📋 Total de películas encontradas: {len(peliculas)}")
    
    resultados = []
    for i, peli in enumerate(peliculas, 1):
        print(f"Procesando película {i}/{len(peliculas)}")
        resultado = procesar_pelicula(peli)
        resultados.append(resultado)
        time.sleep(2)  # evita sobrecarga
        
    guardar_en_json(resultados)
    print("✅ Proceso completado!")

if __name__ == "__main__":
    # Cambia num_paginas para más páginas (cada página tiene 24 películas)
    main(num_paginas=3)  # Por ejemplo, 3 páginas = 72 películas
