package com.mss.supportportal.domain;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import org.springframework.http.HttpStatus;

import java.util.Date;

@Data
public class HttpResponse {

    private int httpStatusCode;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "dd.MM.yyyy HH:mm:ss", timezone = "Europe/Istanbul")
    private Date timestamp;
    private HttpStatus httpStatus;
    private String reason;
    private String message;

    public HttpResponse(int httpStatusCode, HttpStatus httpStatus, String reason, String message){
        timestamp = new Date();
        this.httpStatus = httpStatus;
        this.httpStatusCode = httpStatusCode;
        this.reason = reason;
        this.message = message;
    }
}
