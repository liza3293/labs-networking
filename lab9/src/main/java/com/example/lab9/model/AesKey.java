package com.example.lab9.model;

public class AesKey {
    private String key;
    private String iv;

    public AesKey() {}

    public AesKey(String key, String iv) {
        this.key = key;
        this.iv = iv;
    }

    public String getKey() { return key; }
    public void setKey(String key) { this.key = key; }

    public String getIv() { return iv; }
    public void setIv(String iv) { this.iv = iv; }
}