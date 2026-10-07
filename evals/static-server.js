const http = require("http");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const port = Number(process.env.SAFEPASTE_PORT || 8765);

// Header delivery adds the directives a <meta> CSP cannot enforce.
function securityHeaders() {
  const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
  const meta = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/);
  if (!meta) throw new Error("index.html is missing its Content-Security-Policy meta tag");
  return {
    "Content-Security-Policy": meta[1] + "; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), usb=(), serial=(), bluetooth=()"
  };
}
const headers = securityHeaders();

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8"
};

function resolveRequestPath(requestUrl) {
  let urlPath;
  try {
    urlPath = decodeURIComponent((requestUrl || "/").split("?")[0]);
  } catch (error) {
    return null;
  }
  const relativePath = path.normalize(urlPath === "/" ? "index.html" : urlPath.replace(/^[/\\]+/, ""));
  const absolutePath = path.join(root, relativePath);
  const fromRoot = path.relative(root, absolutePath);

  if (!fromRoot || fromRoot.split(path.sep)[0] === ".." || path.isAbsolute(fromRoot)) {
    return null;
  }

  return absolutePath;
}

const server = http.createServer((request, response) => {
  const filePath = resolveRequestPath(request.url);

  if (!filePath) {
    response.writeHead(403);
    response.end("Forbidden");
    return;
  }

  fs.readFile(filePath, (error, data) => {
    if (error) {
      response.writeHead(404);
      response.end("Not found");
      return;
    }

    response.writeHead(200, Object.assign({}, headers, {
      "Content-Type": contentTypes[path.extname(filePath)] || "text/plain; charset=utf-8",
      "Cache-Control": "no-store"
    }));
    response.end(data);
  });
});

if (require.main !== module) {
  module.exports = { resolveRequestPath, root };
  return;
}

server.listen(port, "127.0.0.1", () => {
  console.log(`SafePaste static verification server: http://127.0.0.1:${port}/`);
});
