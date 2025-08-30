import requests
from bs4 import BeautifulSoup
import re
import base64
import json
import time
import urllib3
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
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
ARCHIVO_JSON = "peliculas_con_reproductores.json"
MAX_WORKERS = 5  # Número de hilos para procesamiento paralelo

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

# --- Función para cargar películas existentes ---
def cargar_peliculas_existentes():
    if not os.path.exists(ARCHIVO_JSON):
        return {}
    
    try:
        with open(ARCHIVO_JSON, "r", encoding="utf-8") as f:
            peliculas_existentes = json.load(f)
        # Crear un diccionario con URL como clave para búsqueda rápida
        return {peli["url"]: peli for peli in peliculas_existentes}
    except (json.JSONDecodeError, FileNotFoundError):
        return {}

# --- Scrap funciones ---
def obtener_urls_peliculas_pagina(num_pagina):
    print(f"🔍 Obteniendo URLs de películas de la página {num_pagina}...")
    url = PELIS_URL_TEMPLATE.format(num_pagina)
    r = session.get(url, verify=False)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    urls_peliculas = []
    
    for a in soup.select("a.Posters-link"):
        enlace = a.get("href")
        if enlace and not enlace.startswith("http"):
            enlace = urljoin(BASE_URL, enlace)
        urls_peliculas.append(enlace)
    
    print(f"  → Encontradas {len(urls_peliculas)} películas en la página {num_pagina}.")
    return urls_peliculas

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

def procesar_pelicula(url_pelicula):
    try:
        r = session.get(url_pelicula, verify=False)
        r.raise_for_status()
        
        # Extraer detalles de la ficha
        detalles = extraer_detalles_pelicula(r.text)
        pelicula = {"url": url_pelicula}
        pelicula.update(detalles)
        
        # Obtener iframe
        iframe_url = obtener_iframe_pelicula(r.text)
        if not iframe_url:
            print(f"  ❌ No se encontró iframe en la página de la película: {detalles.get('titulo', url_pelicula)}")
            pelicula["reproductores"] = []
            return pelicula
        
        # Extraer enlaces reales desde embed69
        r_iframe = session.get(iframe_url, verify=False)
        r_iframe.raise_for_status()
        reproductores = extraer_dataLink(r_iframe.text)
        pelicula["reproductores"] = reproductores
        
        return pelicula
    except Exception as e:
        print(f"  ❌ Error procesando {url_pelicula}: {e}")
        # Devolver una película básica con el error
        return {
            "url": url_pelicula,
            "titulo": f"ERROR: {str(e)}",
            "reproductores": []
        }

def guardar_en_json(data, archivo=ARCHIVO_JSON):
    with open(archivo, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"✅ Guardado en {archivo}")

# --- Main ---
def main(num_paginas=1):
    print(f"🚀 Iniciando scraping de {num_paginas} página(s) con {MAX_WORKERS} hilos...")
    
    # Cargar películas existentes
    peliculas_existentes_dict = cargar_peliculas_existentes()
    print(f"📁 Cargadas {len(peliculas_existentes_dict)} películas existentes desde {ARCHIVO_JSON}")
    
    resultados_finales = []
    nuevas_procesadas = 0
    existentes_reutilizadas = 0
    
    # Recorrer cada página en orden
    for pagina in range(1, num_paginas + 1):
        print(f"\n📄 Procesando página {pagina}/{num_paginas}...")
        
        # Obtener URLs de películas de esta página
        urls_peliculas = obtener_urls_peliculas_pagina(pagina)
        
        # Separar películas nuevas y existentes
        urls_nuevas = []
        peliculas_ordenadas = []
        
        for url_pelicula in urls_peliculas:
            if url_pelicula in peliculas_existentes_dict:
                # La película ya existe, la reutilizamos
                pelicula = peliculas_existentes_dict[url_pelicula]
                peliculas_ordenadas.append(pelicula)
                existentes_reutilizadas += 1
            else:
                # La película no existe, la agregamos a la lista de nuevas
                urls_nuevas.append(url_pelicula)
                # Marcamos un placeholder para mantener el orden
                peliculas_ordenadas.append(None)
        
        print(f"  → {len(urls_nuevas)} películas nuevas para procesar")
        print(f"  → {existentes_reutilizadas} películas existentes reutilizadas")
        
        # Procesar películas nuevas en paralelo
        if urls_nuevas:
            print(f"  ⚡ Procesando {len(urls_nuevas)} películas nuevas en paralelo...")
            
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                # Crear un diccionario para mapear futuros a sus URLs
                future_to_url = {executor.submit(procesar_pelicula, url): url for url in urls_nuevas}
                
                # Procesar resultados a medida que se completan
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        pelicula = future.result()
                        nuevas_procesadas += 1
                        
                        # Encontrar el índice de esta URL en la lista original y reemplazar el placeholder
                        indice = urls_peliculas.index(url)
                        peliculas_ordenadas[indice] = pelicula
                        
                        print(f"    ✅ Completada: {pelicula.get('titulo', url)}")
                    except Exception as e:
                        print(f"    ❌ Error en {url}: {e}")
        
        # Agregar todas las películas de esta página a los resultados finales
        for pelicula in peliculas_ordenadas:
            if pelicula is not None:
                resultados_finales.append(pelicula)
        
        # Pausa entre páginas (más corta ahora)
        if pagina < num_paginas:
            print(f"⏳ Pausa corta antes de la siguiente página...")
            time.sleep(0.5)  # Reducido a 0.5 segundos
    
    print(f"\n📊 Estadísticas finales:")
    print(f"  - Películas nuevas procesadas: {nuevas_procesadas}")
    print(f"  - Películas existentes reutilizadas: {existentes_reutilizadas}")
    print(f"  - Total de películas en el archivo: {len(resultados_finales)}")
    
    guardar_en_json(resultados_finales)
    print("✅ Proceso completado!")

if __name__ == "__main__":
    # Cambia num_paginas para más páginas (cada página tiene 24 películas)
    main(num_paginas=200)  # Por ejemplo, 3 páginas = 72 películas
