package io.quicktype;

import com.fasterxml.jackson.annotation.*;

public class AppSecrets {
    private String databaseURL;

    @JsonProperty("DATABASE_URL")
    public String getDatabaseURL() { return databaseURL; }
    @JsonProperty("DATABASE_URL")
    public void setDatabaseURL(String value) { this.databaseURL = value; }
}
