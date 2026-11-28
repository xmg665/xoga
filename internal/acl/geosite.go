package acl

import "strings"

// BuiltinGeosite provides a zero-heap-bloat compiled dictionary of mainstream streaming & AI
// domains so `geosite:netflix`, `geosite:disney`, `geosite:openai`, etc. work out-of-the-box in
// both `dns.yml` and `routes.toml` without loading an 80+ MiB geosite.dat protobuf into RAM.
var BuiltinGeosite = map[string][]string{
	"netflix": {
		"netflix.com", "netflix.net", "nflximg.com", "nflximg.net",
		"nflxvideo.net", "nflxext.com", "nflxso.net", "fast.com",
	},
	"disney": {
		"disney.com", "disneyplus.com", "disney-plus.net", "dssott.com",
		"bamgrid.com", "disneystreaming.com", "disneyjunior.com", "starplus.com",
	},
	"openai": {
		"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
		"sora.com", "auth0.openai.com",
	},
	"chatgpt": {
		"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "sora.com",
	},
	"anthropic": {
		"anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com",
	},
	"claude": {
		"anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com",
	},
	"gemini": {
		"gemini.google.com", "bard.google.com", "ai.google.dev", "makersuite.google.com",
		"aistudio.google.com", "notebooklm.google.com", "generativeai.google",
		"deepmind.com", "deepmind.google", "generativelanguage.googleapis.com",
		"proactivebackend-pa.googleapis.com", "aisandbox-pa.googleapis.com",
		"alkalimakersuite-pa.clients6.google.com", "alkalicore-pa.clients6.google.com",
		"waa-pa.clients6.google.com", "robinfrontend-pa.googleapis.com",
	},
	"perplexity": {
		"perplexity.ai", "pplx.ai",
	},
	"grok": {
		"x.ai", "grok.com",
	},
	"xai": {
		"x.ai", "grok.com",
	},
	"metaai": {
		"meta.ai", "metaaivm.com", "metaaiusercontent.com",
	},
	"copilot": {
		"copilot.microsoft.com", "bing.com", "sydney.bing.com", "edgeservices.bing.com",
	},
	"youtube": {
		"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
		"youtubei.googleapis.com", "youtube-nocookie.com",
	},
	"google": {
		"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
		"ggpht.com", "1e100.net", "gvt1.com", "gvt2.com",
	},
	"tiktok": {
		"tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com",
		"byteoversea.com", "ibytedtos.com", "ibyteimg.com", "musical.ly",
	},
	"bahamut": {
		"gamer.com.tw", "bahamut.com.tw", "hinet.net",
	},
	"bilibili": {
		"bilibili.com", "biliapi.net", "biliapi.com", "bilivideo.com", "hdslb.com", "b23.tv",
	},
	"hbo": {
		"hbo.com", "hbomax.com", "max.com", "hbogo.com", "hbomaxcdn.com", "warnermediacdn.com",
	},
	"hulu": {
		"hulu.com", "huluim.com", "hulustream.com", "happyon.jp", "hjholdings.tv",
	},
	"primevideo": {
		"primevideo.com", "amazonvideo.com", "aiv-cdn.net", "aiv-delivery.net", "pv-cdn.net",
	},
	"dazn": {
		"dazn.com", "dazn-api.com", "dazndn.com", "indazn.com",
	},
	"abema": {
		"abema.tv", "abema.io", "ameba.jp", "hayabusa.io", "hayabusa.media",
	},
	"dmm": {
		"dmm.com", "dmm.co.jp", "dmm-extension.com",
	},
	"spotify": {
		"spotify.com", "scdn.co", "spotifycdn.com", "pscdn.co",
	},
	"tvb": {
		"tvb.com", "mytvsuper.com",
	},
	"viu": {
		"viu.com", "viu.tv",
	},
	"telegram": {
		"telegram.org", "t.me", "tdesktop.com", "telegra.ph", "telesco.pe",
	},
	"twitter": {
		"twitter.com", "x.com", "twimg.com", "t.co",
	},
	"apple": {
		"apple.com", "icloud.com", "mzstatic.com", "itunes.com", "cdn-apple.com",
	},
}

// ExpandGeosite returns built-in domain suffixes if pattern starts with `geosite:`.
func ExpandGeosite(pattern string) ([]string, bool) {
	p := strings.TrimSpace(pattern)
	if !strings.HasPrefix(strings.ToLower(p), "geosite:") {
		return nil, false
	}
	tag := strings.ToLower(strings.TrimSpace(p[8:]))
	if at := strings.IndexByte(tag, '@'); at > 0 {
		tag = tag[:at]
	}
	if list, ok := BuiltinGeosite[tag]; ok {
		return list, true
	}
	return nil, false
}
