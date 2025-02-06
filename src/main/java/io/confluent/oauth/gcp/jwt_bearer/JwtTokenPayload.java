package io.confluent.oauth.gcp.jwt_bearer;

import com.fasterxml.jackson.annotation.JsonProperty;

public class JwtTokenPayload {

    private String iss;
    private String sub;
    private String aud;
    private long iat;
    private long exp;
    @JsonProperty("target_audience")
    private String targetAudience;

    public JwtTokenPayload(String iss, String sub, String aud, long iat, long exp, String targetAudience) {
        this.iss = iss;
        this.sub = sub;
        this.aud = aud;
        this.iat = iat;
        this.exp = exp;
        this.targetAudience = targetAudience;
    }

    public String getIss() {
        return iss;
    }

    public String getSub() {
        return sub;
    }

    public String getAud() {
        return aud;
    }

    public long getIat() {
        return iat;
    }

    public long getExp() {
        return exp;
    }

    public String getTargetAudience() {
        return targetAudience;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public void setIat(long iat) {
        this.iat = iat;
    }

    public void setExp(long exp) {
        this.exp = exp;
    }

    public void setTargetAudience(String targetAudience) {
        this.targetAudience = targetAudience;
    }
}
