package org.ayakaji.ques.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import org.ayakaji.ques.common.validator.group.AddGroup;
import org.ayakaji.ques.common.validator.group.UpdateGroup;

import javax.validation.constraints.NotBlank;
import java.io.Serializable;
import java.util.Date;

/**
 * 项目实体
 * @author wanglei
 */
@TableName("sat_project")
public class Project implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * 项目ID
     */
    @TableId(value = "proj_id", type = IdType.INPUT)
    private String projId;

    /**
     * 项目名称
     */
    @NotBlank(message="项目名称不能为空", groups = {AddGroup.class, UpdateGroup.class})
    private String projName;

    /**
     * 创建时间
     */
    private Date createTime;

    public String getProjId() {
        return projId;
    }

    public void setProjId(String projId) {
        this.projId = projId;
    }

    public String getProjName() {
        return projName;
    }

    public void setProjName(String projName) {
        this.projName = projName;
    }

    public Date getCreateTime() {
        return createTime;
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }
}
