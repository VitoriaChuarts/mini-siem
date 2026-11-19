package com.vitoria.siem.controller;

import com.vitoria.siem.dto.AlertRequest;
import com.vitoria.siem.model.Alert;
import com.vitoria.siem.repository.AlertRepository;
import com.vitoria.siem.service.CorrelationService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertRepository repository;
    private final CorrelationService correlationService;

    public AlertController(AlertRepository repository, CorrelationService correlationService) {
        this.repository = repository;
        this.correlationService = correlationService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Alert create(@Valid @RequestBody AlertRequest req) {
        Alert alert = new Alert();
        alert.setSource(req.source());
        alert.setTimestamp(req.timestamp());
        alert.setSrcIp(req.srcIp());
        alert.setEventType(req.eventType());
        alert.setSeverity(req.severity());
        alert.setDetails(req.details() == null ? "{}" : req.details().toString());
        Alert salvo = repository.save(alert);
        correlationService.correlacionar(salvo);
        return salvo;
    }

    @GetMapping
    public List<Alert> list(@RequestParam(required = false) String severity,
                            @RequestParam(required = false) String source,
                            @RequestParam(required = false) String ip,
                            @RequestParam(defaultValue = "500") int limit) {
        return repository.findAll(Sort.by(Sort.Direction.DESC, "timestamp")).stream()
                .filter(a -> severity == null || severity.isBlank() || severity.equals(a.getSeverity()))
                .filter(a -> source == null || source.isBlank() || source.equals(a.getSource()))
                .filter(a -> ip == null || ip.isBlank() || ip.equals(a.getSrcIp()))
                .limit(Math.max(1, Math.min(limit, 500)))
                .toList();
    }
}
