package modify

import (
	"encoding/binary"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"goLdapTools/cli/global"
	"goLdapTools/conn"
	"goLdapTools/log"
	"goLdapTools/search"
	"goLdapTools/transform/sddl"
	"goLdapTools/transform/sddl/sid"
	"strings"
)

type DcSyncAddConfig struct {
	Target    string
	Global    *global.GlobalCommand
	Connector *conn.Connector
}

// AppendADSddl 添加ACL
func AppendADSddl(globalConfig *global.GlobalCommand, conn *conn.Connector, controls []ldap.Control, user string, controlAccess string) error {
	us := search.NewPluginBase(
		fmt.Sprintf("(&(objectclass=person)(sAMAccountName=%s))", user),
		[]string{"objectSid"}, &search.SearchConfig{
			Global:    globalConfig,
			Attr:      nil,
			Connector: nil,
		})
	userEntries, err := us.Search(conn, nil)
	if err != nil {
		log.PrintErrorf("search target user sid error: %s", err.Error())
		return err
	}

	userSid := ""
	for _, entry := range userEntries {
		for _, v := range entry.Attributes {
			if v.Name == "objectSid" {
				userSid = sid.SidToString(v.ByteValues[0])
			}
		}
	}
	log.PrintDebugf("get %s sid: %s", user, userSid)

	// 搜索DcSync
	property := search.NewPluginBase("(objectClass=domain)", []string{"nTSecurityDescriptor"},
		&search.SearchConfig{
			Global:    globalConfig,
			Attr:      nil,
			Connector: nil,
		})
	entries, err := property.Search(conn, controls)
	if err != nil {
		log.PrintErrorf("search all user error: %s", err.Error())
		return err
	}

	// 追加SDDL
	for _, entry := range entries {
		for _, v := range entry.Attributes {
			if v.Name == "nTSecurityDescriptor" {
				// 读取原始SDDL
				oldSr, err := sddl.NewSecurityDescriptor(v.ByteValues[0])
				if err != nil {
					log.PrintErrorf("%s\n%s\n", "resolve nTSecurityDescriptor error:", err.Error())
					return err
				}

				dumpString := oldSr.DataToString(v.ByteValues[0])
				log.PrintDebugf("dump user string: %s", dumpString.String())

				// 检查原始SDDL中是否已存在带添加ACE权限
				hasPriv := false
				for _, ace := range oldSr.Dacl.Aces {
					// 先找到用户
					if strings.EqualFold(ace.SID.Value.(string), userSid) {
						if ace.ObjectType != nil && strings.EqualFold(controlAccess, ace.ObjectType.Value.(string)) {
							hasPriv = true
							log.PrintInfof("%s has already right", user)
						}
					}
				}

				// 创建新的Ace，将新的Ace追加到原来的SDDL数据中，整理原ADDL，转换为字节
				if !hasPriv {
					// 添加一条DACL ace，更新对应Dacl中原始数据
					aceSize, err := oldSr.Dacl.AddAce(userSid, controlAccess)
					if err != nil {
						return err
					}

					// 再更新 offsetOwner/OffsetGroup 偏移、原始数据
					if oldSr.OffsetOwner.Value.(uint32) != 0 {
						oldSr.OffsetOwner.Value = oldSr.OffsetOwner.Value.(uint32) + uint32(aceSize)
						offsetOwnerRaw := make([]byte, 4)
						binary.LittleEndian.PutUint32(offsetOwnerRaw, oldSr.OffsetOwner.Value.(uint32))

						oldSr.OffsetOwner.RawData = offsetOwnerRaw
					}
					if oldSr.OffsetGroup.Value.(uint32) != 0 {
						oldSr.OffsetGroup.Value = oldSr.OffsetGroup.Value.(uint32) + uint32(aceSize)
						offsetGroupRaw := make([]byte, 4)
						binary.LittleEndian.PutUint32(offsetGroupRaw, oldSr.OffsetGroup.Value.(uint32))

						oldSr.OffsetGroup.RawData = offsetGroupRaw
					}

					// 创建新的SDDL数据
					newRawData, err := oldSr.GetData()
					if err != nil {
						return err
					}

					// 修改域控属性
					err = conn.DoModify(conn.Config.BaseDN, controls, "nTSecurityDescriptor", []string{string(newRawData)})
					if err != nil {
						return err
					}

					log.PrintSuccessf("add sddl %s success. ace id: %s", user, controlAccess)
				}
			}
		}
	}

	return nil
}
