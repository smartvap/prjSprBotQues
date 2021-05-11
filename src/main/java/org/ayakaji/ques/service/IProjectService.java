package org.ayakaji.ques.service;

import com.baomidou.mybatisplus.extension.service.IService;
import org.ayakaji.ques.entity.Project;

import java.util.List;

/**
 * 项目Service接口
 * @author wanglei
 */
public interface IProjectService extends IService<Project> {
    /**
     * 获取项目列表
     * @return List<Project>
     */
    List<Project> getProject();
}
