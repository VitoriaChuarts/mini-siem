package com.vitoria.siem.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.time.Instant;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String source;      // honeypot, nids ou phishing
    private Instant timestamp;
    private String srcIp;
    private String eventType;
    private String severity;

    @Column(columnDefinition = "TEXT")
    private String details;     // JSON guardado como texto
}
