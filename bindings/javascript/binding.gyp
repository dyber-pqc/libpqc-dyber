{
  "targets": [
    {
      "target_name": "pqc_addon",
      "sources": ["src/addon.c"],
      "include_dirs": ["../../include"],
      "conditions": [
        ["OS=='win'", {
          "libraries": ["-lpqc"],
          "library_dirs": ["../../build/Release"]
        }],
        ["OS=='linux' or OS=='mac'", {
          "libraries": ["-lpqc"],
          "library_dirs": ["../../build"]
        }]
      ],
      "cflags": ["-std=c11"],
      "defines": ["NAPI_VERSION=8"]
    }
  ]
}
