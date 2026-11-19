package com.vitoria.siem.controller;

import com.vitoria.siem.repository.AlertRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/stats")
public class StatsController {

    private final AlertRepository repository;

    public StatsController(AlertRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    public Map<String, Object> stats() {
        Map<String, Object> resultado = new LinkedHashMap<>();
        resultado.put("total", repository.count());
        resultado.put("porSeveridade", repository.contarPorSeveridade());
        resultado.put("porFonte", repository.contarPorFonte());
        resultado.put("topIps", repository.topIps(PageRequest.of(0, 5)));
        return resultado;
    }
}
