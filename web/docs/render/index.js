class Utils {
    static uuid(len, radix) {
        var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('');
        var uuid = [], i;
        radix = radix || chars.length;
     
        if (len) {
            for (i = 0; i < len; i++) uuid[i] = chars[0 | Math.random()*radix];
        } else {
            var r;
            uuid[8] = uuid[13] = uuid[18] = uuid[23] = '-';
            uuid[14] = '4';
            for (i = 0; i < 36; i++) {
                if (!uuid[i]) {
                    r = 0 | Math.random()*16;
                    uuid[i] = chars[(i == 19) ? (r & 0x3) | 0x8 : r];
                }
            }
        }
        return uuid.join('').toLocaleLowerCase();
    }
    static isDOM(o) {
        return (
            typeof HTMLElement === "object" ? o instanceof HTMLElement : //DOM2
            o && typeof o === "object" && o !== null && o.nodeType === 1 && typeof o.nodeName==="string"
        );
    }
}
class I18NManager {
    constructor() {
        this._i18n = {}
        this._lang = "zh_CN"
    }
    addLangage(lang, key, value) {
        if (!(lang in this._i18n)) {
            this._i18n[lang] = {}
        }
        this._i18n[lang][key] = value;
    }
    addLanguageTable(lang, table) {
        Object.entries(table).forEach(([key, value]) => {
            this.addLangage(lang, key, value)
        })
    }
    t(key, params) {
        if (!(this._lang in this._i18n)) {
            return key;
        }
        var value = this._i18n[this._lang][key];
        if (value == null) {
            return key;
        }
        Object.entries(params || {}).forEach(([key, v]) => {
            value = value.replaceAll(`%${key}%`, v);
        })
        return value;
    }
    setLang(lang) {
        this._lang = lang;
        window.dispatchEvent(new CustomEvent("langChange", { detail: lang }))
    }
}
class ElementManager {
    constructor() {
        this._elements = []
        window.addEventListener("langChange", (event) => {
            this._elements.forEach(element => element._render_i18n())
        })
    }
    add(element) {
        this._elements.push(element);
    }
}
class Element {
    constructor(object) {
        if (typeof object == "string") {
            this._base = document.createElement(object);
        } else if (Utils.isDOM(object)) {
            this._base = object;
        } else {
            console.log(object)
        }
        this._i18n_key = null;
        this._i18n_params = {};
        this._children = []
        $ElementManager.add(this);
    }
    get origin() {
        return this._base;
    }
    html(html) {
        this._base.innerHTML = html;
        return this;
    }
    text(text) {
        this._base.innerText = text;
        return this;
    }
    i18n(key, params = {}) {
        this._i18n_key = key;
        this._i18n_params = params;
        this._render_i18n();
        return this;
    }
    t18n(params) {
        this._i18n_params = params || {};
        this._render_i18n();
        return this;
    }
    _render_i18n() {
        if (this._i18n_key == null) {
            return;
        }
        this.text($i18n.t(this._i18n_key, this._i18n_params))
    }
    append(...elements) {
        elements.forEach(element => {
            if (Utils.isDOM(element)) {
                element = new Element(element);
            }
            this._children.push(element);
            this._base.appendChild(element.origin);
        })
        return this
    }
    classes(...classes) {
        this._base.classList.add(...classes);
        return this;
    }
    removeClasses(...classes) {
        this._base.classList.remove(...classes);
        return this;
    }
    hasClasses(...classes) {
        console.log(classes, this._base.classList.contains(...classes), this._base.classList)
        return this._base.classList.contains(...classes);
    }
    toggle(...classes) {
        this._base.classList.toggle(...classes);
        return this;
    }
    style(key, value) {
        this._base.style[key] = value;
        return this;
    }
    addEventListener(event, handler) {
        this._base.addEventListener(event, handler);
        return this;
    }
    get children() {
        return this._children;
    }
    get length() {
        return this._children.length;
    }
    removeChild(object) {
        // first number
        // second dom
        // last element
        if (typeof object == "number") {
            this._children.splice(object, 1);
        } else if (Utils.isDOM(object)) {
            this._children.splice(this._children.indexOf(new Element(object)), 1);
        } else {
            this._children.splice(this._children.indexOf(object), 1);
        }
        this._base.removeChild(object.origin);
        return this
    }
    get firstChild() {
        return this._children[0];
    }
    get lastChild() {
        return this._children[this._children.length - 1];
    }
    remove() {
        this._children.forEach(child => child.remove());
        this._base.remove();
    }
    clear() {
        this._children.forEach(child => child.remove());
        this._base.html("")
        this.removeClasses(
            ...this._base.classList.values()
        )
    }
    appendBefore(element) {
        this._children.unshift(element);
        this._base.insertBefore(element.origin, this._base.firstChild);
        return this
    }
    attributes(attributes) {
        Object.entries(attributes).forEach(([key, value]) => {
            this._base.setAttribute(key, value);
        })
        return this;
    }
}
class Configuration {
    constructor() {
        // use local storage
    }
    get(key, _def) {
        var item = localStorage.getItem(key) != null ? JSON.parse(localStorage.getItem(key)) : {
            value: _def
        };
        return item.value;
    }
    set(key, value) {
        localStorage.setItem(key, JSON.stringify({
            "value": value,
            "timestamp": new Date()
        }));
    }
}
class Style {
    constructor() {
        this._styles = {}
        this._style_dom = document.createElement("style");
        this._style_sheet = this._style_dom.sheet;
        this._themes = {}
        this._current_theme = null;
        this.applyTheme($configuration.get("theme", window.matchMedia("(prefers-color-scheme: dark)") ? "dark" : "light"))
        document.getElementsByTagName("head").item(0).appendChild(this._style_dom);
    }
    _parseToString(object) {
        if (Array.isArray(object)) {
            return object.map(this._parseToString).join(";");
        } else if (typeof object == "object") {
            return Object.entries(object).map(([key, value]) => `${key}:${this._parseToString(value)}`).join(";");
        } else {
            return object.toString();
        }
    }
    add(name, style) {
        this._styles[name] = this._parseToString(style);
        this.render();
    }
    addAll(styles) {
        Object.entries(styles).forEach(([name, style]) => this.add(name, style));
    }
    render() {
        const theme = {};
        Object.entries(this._themes[this._current_theme] || {}).forEach(([key, value]) => {
            theme[`--${key}`] = value;
        })
        this._styles[":root"] = this._parseToString(theme); 
        const styleRules = Object.entries(this._styles).map(([name, style]) => style == null ? "" : `${name}{${style}}`.replaceAll(/\n|\t|\r/g, "").replaceAll(/\s\s/g, " "));
        requestAnimationFrame(() => {
            this._clear_render();
            styleRules.forEach(styleRule => {
                this._sheet_render(styleRule);
            });   
        })
    }
    _clear_render() {
        this._style_sheet = this._style_dom.sheet;
        if (this._style_sheet) {
            this._clear_render = () => {
                while (this._style_sheet.cssRules.length > 0) {
                    this._style_sheet.deleteRule(0);
                }
            }
        } else {
            this._clear_render = () => {
                while (this._style_dom.childNodes.length > 0) {
                    this._style_dom.removeChild(this._style_dom.childNodes[0]);
                }
            }
        }
        this._clear_render()
    }
    _sheet_render(styleRule) {
        this._style_sheet = this._style_dom.sheet;
        if (this._style_sheet) {
            try {
                var handler = (styleRule) => {
                    this._style_sheet.insertRule(styleRule, this._style_sheet.cssRules.length);
                }
                handler(styleRule)
                this._sheet_render = handler;
                return;
            } catch (e) {
                console.log(e)
            }
        }
        this._sheet_render = (styleRule) => this._style_dom.appendChild(document.createTextNode(styleRule));
        this._sheet_render()
    }
    applyTheme(name) {
        this._current_theme = name || Object.keys(this._themes)[0];
        this.render();
    }
    setTheme(name, style) {
        this._themes[name] = style;
    }
}
class SVGContainers {
    static _parse(element) {
        return new Element(document.createRange().createContextualFragment(element).childNodes[0]);
    }
    static get menu() {
        return SVGContainers._parse('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path d="M4 6h16v2H4zm0 5h16v2H4zm0 5h16v2H4z"></path></svg>')
    }
    static get moon() {
        return SVGContainers._parse('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path d="M12 11.807A9.002 9.002 0 0 1 10.049 2a9.942 9.942 0 0 0-5.12 2.735c-3.905 3.905-3.905 10.237 0 14.142 3.906 3.906 10.237 3.905 14.143 0a9.946 9.946 0 0 0 2.735-5.119A9.003 9.003 0 0 1 12 11.807z"></path></svg>')
    }
    static get sun() {
        return SVGContainers._parse('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path d="M6.995 12c0 2.761 2.246 5.007 5.007 5.007s5.007-2.246 5.007-5.007-2.246-5.007-5.007-5.007S6.995 9.239 6.995 12zM11 19h2v3h-2zm0-17h2v3h-2zm-9 9h3v2H2zm17 0h3v2h-3zM5.637 19.778l-1.414-1.414 2.121-2.121 1.414 1.414zM16.242 6.344l2.122-2.122 1.414 1.414-2.122 2.122zM6.344 7.759 4.223 5.637l1.415-1.414 2.12 2.122zm13.434 10.605-1.414 1.414-2.122-2.122 1.414-1.414z"></path></svg>')
    }
}
class Progressbar extends Element {
    constructor() {
        super("div")
        $style.addAll({
            ".progressbar": {
                "width": "100%",
                "height": "2px",
                "background": "var(--background)",
                "position": "absolute",
                "top": "0",
                "left": "0",
                "z-index": "9999"
            },
            ".progressbar > div": {
                "width": "0",
                "height": "100%",
                "background": "var(--main-color)",
                "transition": "width 0.5s ease-in-out"
            }
        })
        this.classes("progressbar")
        this._child = createElement("div")
        this._child.style("--progress", 0)
        this.append(this._child)
        this.set(0)
        this._clear = null
    }
    set(progress) {
        if (this._clear != null) {
            clearTimeout(this._clear)
            this._clear = null
        }
        requestAnimationFrame(() => {
            this._child.style("width", progress + "%")
        })
    }
    clear() {
        if (this._clear) {
            clearTimeout(this._clear)
            this._clear = null
        }
        this._clear = setTimeout(() => {
            this.set(0)
            requestAnimationFrame(() => {
                this._child.style("width", 0)
            })
        }, 1000)
    }
}
function createElement(object) {
    return new Element(object);
}
function raf(func) {
    // 防抖，使用requestAnimationFrame
    let timer = null;
    return ((...args) => {
        if (timer) return;
        timer = requestAnimationFrame(() => {
            func(...args);
            timer = null;
        })
    })
}
const $configuration = new Configuration();
const $ElementManager = new ElementManager();
const $style = new Style();
const $i18n = new I18NManager();
const $title = document.title
const $progressbar = new Progressbar()
$i18n.addLanguageTable("zh_CN", {
    "footer.copyright": "%name% © %begin% - %end%, All Rights Reserved.",
    "main.side.router_root": "%prefix%",
    "main.side.route": "%path%",
    "main.side.mount": "挂载 [%path%]",
})
$style.setTheme("light", {
    "main-color": "rgb(15, 198, 194)",
    "text-color": "#ffffff",
    "color": "rgba(0, 0, 0, 0.7)",
    "background": "#F5F6F8",
    "footer-background": "#F0F0F0",
    "main-dark-color": "rgb(10, 157, 220)",
    "main-shadow-.2-color": "rgba(15, 198, 194, 0.2)"
})
$style.setTheme("dark", {
    "main-color": "rgb(244, 209, 180)",
    "text-color": "#000000",
    "color": "#ffffff",
    "background": "#181818",
    "footer-background": "#202020",
    "main-dark-color": "rgb(235, 187, 151)",
    "main-shadow-.2-color": "rgba(244, 209, 180, 0.2)"

})
$style.addAll({
    "::-webkit-scrollbar, html ::-webkit-scrollbar": {
        "width": "5px",
        "height": "5px",
        "border-radius": "10px"
    },
    "::-webkit-scrollbar-thumb, html ::-webkit-scrollbar-thumb": {
        "box-shadow": "rgba(0, 0, 0, 0) 0px 0px 6px inset",
        "background-color": "rgb(102, 102, 102)",
        "border-radius": "10px",
    },
    "body": {
        "overflow": "hidden"
    },
    ".app": {
        "display": "flex",
        "flex-direction": "column",
        "flex-wrap": "nowrap",
        "justify-content": "space-between",
        "height": "100vh",
        "width": "100vw",
        "background": "var(--background)",
        "overflow-y": "auto"
    },
    "a": {
        "color": "var(--color)",
        "text-decoration": "none"
    },
    "a:hover": {
        "text-decoration": "underline"
    },
    "header": `
        background-color: var(--background);
        text-align: center;
        min-height: 56px;
        width: 100%;
        padding: 8px 8px 8px 8px;
        z-index: 1;
        display: flex;
        align-items: center;
        flex-wrap: nowrap;
        justify-content: space-between
    `,
    "header .content": {
        "display": "flex",
        "align-items": "center"
    },
    "header svg": {
        "width": "48px",
        "height": "48px",
        "padding": "8px", 
        "cursor": "pointer"
    },
    "header .padding-left": {
        "padding-left": "8px",
    },
    "header span": {
        "background-color": "rgb(0, 0, 0, 0.15)",
        "width": "1px",
        "height": "40px"
    },
    "h1,h2,h3,h4,h5,h6,p": "margin:0;color:var(--color)",
    "svg": {
        "fill": "var(--color)"
    },
    "main": {
        "top": "56px",
        "display": "flex",
    },
    "footer": {
        "padding": "24px",
        "flex-direction": "column",
        "background": "var(--footer-background)",
        "color": "var(--color)",
        "display": "flex",
        "align-items": "center",
        "justify-content": "center"
    },
    ".side": {
        "width": "220px",
        "height": "100%",
        "padding-left": "20px",
        "background": "var(--background)",
        "overflow-y": "auto",
        "border-right": "1px solid var(--color)",
        "transform": "translateX(0%)",
        "transition": "transform 150ms cubic-bezier(0.4, 0, 0.2, 1);"
    },
    ".side.hide": {
        "transform": "translateX(-100%)",
    },
    "@media screen and (max-width: 768px)": {
        ".side": {
            "position": "fixed",
        },
    },
    ".side .router-root": {
        "font-size": "14px",
        "height": "46px",
        "color": "var(--color)",
        "padding": "16px 6px",
        "cursor": "pointer",
        "display": "flex",
        "align-items": "center",
        "text-align": "left",
        "padding": "8px 16px",
        "border-radius": "4px",
        "transition": "color 150ms cubic-bezier(0.4, 0, 0.2, 1)"
    },
    ".side .router-root:hover": {
        "color": "var(--main-color)",
    },
    ".side .router-root.selected": {
        "color": "var(--dark-color)",
        "background": "var(--main-color)",
        "box-shadow": "var(--main-shadow-.2-color) 0px 10px 25px 0px",
    },
    ".side .router-container": {
        "height": "0",
        "overflow": "hidden",
        "transition": "height 300ms cubic-bezier(0.4, 0, 0.2, 1)"
    },
    ".side .router-route": {
        "color": "var(--color)",
        "padding": "8px 24px 8px 16px",
    }
})

async function request(method, url, data, headers = {}) {
    return new Promise((resolve, reject) => {
        var xhr = new XMLHttpRequest()
        xhr.addEventListener("progress", function (event) {
            $progressbar.set(75 + (event.loaded / event.total * 100) / 25)
            if (event.loaded == event.total) {
                $progressbar.clear()
            }
        })
        xhr.addEventListener("readystatechange", function (event) {
            $progressbar.set(event.target.readyState * 25)
            if (event.target.readyState == 4) {
                $progressbar.clear()
                resolve(event.target)
            }
        })
        xhr.open(method, url)
        Object.entries(headers).forEach(([key, value]) => {
            xhr.setRequestHeader(key, value)
        })
        xhr.send(data)
    })
}

async function load() {
    const $prefix = (window.location.pathname.endsWith("/") != -1 ? window.location.pathname : window.location.pathname.slice(0, -1))
    const $dom_body = new Element(document.body);

    const $app = createElement("div").classes("app")

    const $header = createElement("header")
    const $menu = SVGContainers.menu.addEventListener(
        "click",
        () => $side.toggle("hide")
    )
    const $theme = {
        sun: SVGContainers.sun,
        moon: SVGContainers.moon
    }
    const $theme_change = createElement("div").append(
        $theme[$configuration.get("theme") == "light" ? "moon" : "sun"]
    )
    for (const $theme_key in $theme) {
        $theme[$theme_key].addEventListener("click", () => {
            $theme_change.removeChild($theme[$theme_key]);
            $style.applyTheme($theme_key == "sun" ? "light" : "dark");
            $theme_change.append($theme[$theme_key == "sun" ? "moon" : "sun"]);
            $configuration.set("theme", $theme_key == "sun" ? "light" : "dark");
        })
    }
    const $header_content_left = createElement("div").classes("content").append(
        $menu,
        createElement("span"),
        createElement("h3").text($title).classes("padding-left")
    );
    const $header_content_right = createElement("div").classes("content").append(
        $theme_change
    );
    $header.append($header_content_left, $header_content_right);
    const $main = createElement("main")
    const $footer = createElement("footer").append(
        createElement("p").i18n(
            "footer.copyright"
        ).t18n({
            "name": "TTB - Network",
            "begin": "2022",
            "end": "2024"
        })
    )

    $app.append(
        createElement("container").append(
            $progressbar,
            $header,
            $main,
        ),
        $footer
    );

    $dom_body.appendBefore($app);

    const $routers = JSON.parse(
        (
            await request("GET", `${$prefix}`, null, {
                "Content-Type": "application/json"
            })
        ).response
    )
    const $side_reset = () => {
        console.log($side)
        $side.children.filter(e => e.hasClasses("router-container")).forEach(e => {
            e.style("height", "0px")
        })
    }

    const $side = createElement("div").classes("side")
    $routers.forEach(router => {
        console.log(router)
        let $root = createElement("div").classes("router-root")
        let $root_containers = createElement("div").classes("router-container")
        $root.i18n(
            "main.side.router_root"
        ).t18n({
            "prefix": router.prefix
        })
        router.routes.forEach(route => {
            let $route = createElement("div").classes("router-route").append(
                createElement("p").i18n(
                    "main.side.route"
                ).t18n({
                    "method": route.method,
                    "path": route.path
                })
            )
            $root_containers.append($route)
        })
        $side.append($root, $root_containers)
        $root.addEventListener("click", () => {
            if ($root.hasClasses("selected")) {
                return;
            }
            $side_reset()
            $root.classes("selected")
            $root_containers.style("height", "auto")
            var height = calcElementHeight($root_containers)
            $root_containers.style("height", "0px")
            requestAnimationFrame(() => {
                $root_containers.style("height", `${height}px`)
            })
        })
    })
    $main.append($side)

    const observer = new ResizeObserver((..._) => {
        var header = calcElementHeight($header)
        var footer = calcElementHeight($footer)
        var height = window.innerHeight - header - footer
        $main.style("height", `${height}px`)
    });
    observer.observe($app.origin, { childList: true, subtree: true });

    $side_reset();
}
function calcElementHeight(element) {
    var origin = element.origin;
    var rect = origin.getBoundingClientRect()
    return rect.height
    
}
function parseComputedStyleRect(value) {
    // ends px
    if (value.endsWith("px")) {
        return parseInt(value.slice(0, -2))
    } else if (value.endsWith("vw")) {
        var percent = parseInt(value.slice(0, -2))
        return window.innerWidth * percent / 100
    } else if (value.endsWith("vh")) {
        var percent = parseInt(value.slice(0, -2))
        return window.innerHeight * percent / 100
    } else {
        try {
            return +value
        } catch (e) {
            return value
        }
    }
}
window.addEventListener("DOMContentLoaded", async () => {
    await load()
    Array.from(document.getElementsByClassName("preloader")).forEach(e => {
        const element = new Element(e);
        requestAnimationFrame(() => {
            element.classes("hidden");
            setTimeout(() => {
                element.remove();
            }, 1000)
        })
    })
})

globalThis.$configuration = $configuration;
globalThis.$ElementManager = $ElementManager;
globalThis.$style = $style;
globalThis.$i18n = $i18n;
