package testfixture

import "encoding/json"

const JavaScriptBundlerSource = `(self.webpackChunkDemo=self.webpackChunkDemo||[]).push([[1,chunk],{
  0:function(m,e,r){r(1);r.e("lazy");r.d(e,{answer:()=>42});m.exports={name:"demo"};e.other=1;function shadow(r){r(99)}},
  1:(m,e,r)=>{e.value=42}
},function(r){r(0);r.e("boot");function nested(){r(77)}}]);`

func JavaScriptBundlerASAR() []byte {
	content := []byte(JavaScriptBundlerSource)
	header, _ := json.Marshal(map[string]any{"files": map[string]any{"bundle.js": map[string]any{"size": len(content), "offset": "0"}}})
	return ASAR(string(header), content)
}
