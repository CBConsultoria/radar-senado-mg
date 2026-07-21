// protect.js — decripta o conteúdo desta página usando a chave de sessão
// gerada em index.html após a senha correta. Se não houver chave em sessão,
// volta para o login.
//
// Em vez de document.write() (que não garante a ordem de execução de
// <script src="..."> externos, como o Chart.js, em relação aos scripts
// inline que dependem deles), este arquivo faz o parse do HTML decriptado
// e reconstrói a página nó a nó, executando os <script> em ordem e
// esperando cada script externo terminar de carregar antes de seguir
// para o próximo. Isso evita que gráficos e outros elementos dependentes
// de JS "desapareçam" por causa de timing.

(function () {
  function b64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  async function importSessionKey() {
    const raw = sessionStorage.getItem("_k");
    if (!raw) return null;
    try {
      const keyBytes = b64ToBytes(raw);
      return await crypto.subtle.importKey(
        "raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]
      );
    } catch (e) {
      return null;
    }
  }

  function runScript(oldScript) {
    return new Promise((resolve) => {
      const newScript = document.createElement("script");
      for (const attr of Array.from(oldScript.attributes)) {
        newScript.setAttribute(attr.name, attr.value);
      }
      if (oldScript.src) {
        newScript.onload = () => resolve();
        newScript.onerror = () => resolve(); // não trava a página se um script falhar
        document.body.appendChild(newScript);
      } else {
        newScript.textContent = oldScript.textContent;
        document.body.appendChild(newScript);
        // scripts inline executam de forma síncrona ao serem inseridos
        resolve();
      }
    });
  }

  async function injectHTML(htmlString) {
    const parsed = new DOMParser().parseFromString(htmlString, "text/html");

    if (parsed.title) document.title = parsed.title;

    // Copia tudo do <head> exceto <script> (que é tratado separadamente,
    // na ordem correta, junto com os scripts do <body>)
    document.head.innerHTML = "";
    for (const node of Array.from(parsed.head.childNodes)) {
      if (node.tagName === "SCRIPT") continue;
      document.head.appendChild(node.cloneNode(true));
    }

    // Copia o conteúdo do <body>, também sem os <script>
    document.body.innerHTML = "";
    for (const node of Array.from(parsed.body.childNodes)) {
      if (node.tagName === "SCRIPT") continue;
      document.body.appendChild(node.cloneNode(true));
    }

    // Executa todos os <script> (do head e do body, nessa ordem) um a um,
    // esperando scripts externos carregarem antes de seguir para o próximo
    const scripts = [
      ...parsed.head.querySelectorAll("script"),
      ...parsed.body.querySelectorAll("script"),
    ];
    for (const oldScript of scripts) {
      await runScript(oldScript);
    }
  }

  async function decryptPage(rootDepth) {
    const key = await importSessionKey();
    if (!key) {
      const back = "../".repeat(rootDepth) + "index.html";
      window.location.href = back + "?next=" + encodeURIComponent(window.location.pathname);
      return;
    }
    try {
      const iv = b64ToBytes(window.__PAGE_PAYLOAD__.iv);
      const ciphertext = b64ToBytes(window.__PAGE_PAYLOAD__.ciphertext);
      const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ciphertext);
      const html = new TextDecoder().decode(decrypted);
      await injectHTML(html);
    } catch (e) {
      const back = "../".repeat(rootDepth) + "index.html";
      sessionStorage.removeItem("_k");
      window.location.href = back;
    }
  }

  window.__decryptPage = decryptPage;
})();
