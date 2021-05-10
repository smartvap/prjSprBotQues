package org.ayakaji.ques.controller;

import org.ayakaji.ques.entity.Project;
import org.ayakaji.ques.service.IProjectService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.util.List;



/**
 * 项目管理
 * @author wanglei
 */
@RestController
@RequestMapping("/survey/project")
public class ProjectController {
    @Autowired
    private IProjectService iProjectService;

    /**
     * 项目列表
     */
    @GetMapping("/list")
    public ResponseEntity<Object> list() throws UnsupportedEncodingException {
        List<Project> list = iProjectService.getProject();
        return new ResponseEntity<>(list, HttpStatus.OK);
    }

}
