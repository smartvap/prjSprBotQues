package org.ayakaji.ques.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.ayakaji.ques.entity.Project;
import org.ayakaji.ques.mapper.ProjectMapper;
import org.ayakaji.ques.service.IProjectService;
import org.springframework.stereotype.Service;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * 项目Service
 * @author wanglei
 */
@Service("projectService")
public class ProjectServiceImpl extends ServiceImpl<ProjectMapper, Project> implements IProjectService {
    @Override
    public List<Project> getProject() {
        String beginTime = getTimes(0);
        String endTime = getTimes(1);
        QueryWrapper<Project> queryWrapper = new QueryWrapper<>();
        queryWrapper.between("create_time",beginTime,endTime);
        return baseMapper.selectList(queryWrapper);
    }

    /**
     * 获取时间 num:1代表明天 num:0代表今天
     * @param num
     * @return String
     */
    private String getTimes(int num) {
        Date date=new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.DATE,num);
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
        return formatter.format(calendar.getTime());
    }
}
