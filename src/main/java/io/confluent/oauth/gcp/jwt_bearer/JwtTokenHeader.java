package io.confluent.oauth.gcp.jwt_bearer;

public class JwtTokenHeader {
    private String alg;
    private String typ;
    private String kid;

    public JwtTokenHeader(String alg, String typ, String kid) {
        this.alg = alg;
        this.typ = typ;
        this.kid = kid;
    }

    public String getAlg() {
        return alg;
    }

    public String getTyp() {
        return typ;
    }

    public String getKid() {
        return kid;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public void setTyp(String typ) {
        this.typ = typ;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }
}
