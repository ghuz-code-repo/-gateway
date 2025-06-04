package models

import (
	"fmt"
	"os"
)

// EmailTemplate holds data for formatting an email
type EmailTemplate struct {
	Subject   string
	Recipient string
	FullName  string
	Content   string
	Footer    string
}

// GetFormattedEmail returns a formatted email message
func GetFormattedEmail(template EmailTemplate) string {
	// Default footer if not provided
	footer := template.Footer
	if footer == "" {
		footer = "If you have any questions, please contact the system administrator."
	}

	return fmt.Sprintf(`
Dear %s,

%s

Best regards,
Golden House IT Team

--
%s
    `, template.FullName, template.Content, footer)
}

// GetAccountCreatedEmail returns a formatted email for account creation
func GetAccountCreatedEmail(fullName, username, password string, roles []string) (string, string) {
	rolesStr := fmt.Sprintf("%v", roles)

	subject := "Вы были добавлены в систему утилит отдела аналитики и развития Golden House"

	content := fmt.Sprintf(`
Здравствуйте, %s!

Добро пожаловать в систему утилит отдела аналитики и развития компании Golden House! Ваша учетная запись была успешно создана.

Данные учетной записи:
- Ссылка для входа: https://analytics.gh.uz/
- Дополнительня ссылка для входа (если ссылка сверху не работает): https://06sz6qcb-80.euw.devtunnels.ms/
- Имя пользователя: %s
- Пароль: %s
- Полное имя: %s
- Роли: %s

На текущий момент система находится на финальной стадии тестирования, и вы можете использовать ей по ссылке http://analytics.gh.uz/

По любым вопросам связанным с системой вы можете обратиться на почту %s или написать в телеграм %s.

С уважением,
	Команда отдела аналитики и развития Golden House


Это автоматическое сообщение, пожалуйста, не отвечайте на него.
		`, fullName, username, password, fullName, rolesStr, os.Getenv("SUPPORT_EMAIL"), os.Getenv("SUPPORT_TELEGRAM"))

	return subject, content
}

// GetAccountUpdatedEmail returns a formatted email for account updates
func GetAccountUpdatedEmail(fullName, username, email, password string, roles []string) (string, string) {
	rolesStr := fmt.Sprintf("%v", roles)

	subject := "Ваш аккаунт в системе утилит отдела аналитики и развития Golden House был изменён"

	// Password message
	passwordMsg := ""
	if password != "" {
		passwordMsg = fmt.Sprintf("Ваш пароль был обновлен на: %s", password)
	}

	content := fmt.Sprintf(`
Здравствуйте %s,

Ваша учетная запись в системе утилит отдела аналитики и развития Golden House была обновлена.
	- Ссылка для входа: https://analytics.gh.uz/
	- Дополнительня ссылка для входа (если ссылка сверху не работает): https://06sz6qcb-80.euw.devtunnels.ms/
	- Имя пользователя: %s
	- Ваши текущие роли: %s
	%s

Если вы не запрашивали эти изменения, пожалуйста, немедленно свяжитесь по почте %s или напишите в телеграм %s.

С уважением,
	Команда отдела аналитики и развития Golden House

Это автоматическое сообщение, пожалуйста, не отвечайте на него.
`, fullName, username, rolesStr, passwordMsg, os.Getenv("SUPPORT_EMAIL"), os.Getenv("SUPPORT_TELEGRAM"))

	return subject, content
}

// GetAccountDeletedEmail returns a formatted email for account deletion
func GetAccountDeletedEmail(fullName, username string) (string, string) {
	subject := "Ваша учетная запись в системе утилит отдела аналитики и развития Golden House была удалена"

	content := fmt.Sprintf(`
Здравствуйте %s,

Ваша учетная запись системе утилит отдела аналитики и развития Golden House была удалена.

Детали учетной записи:
- Имя пользователя: %s

Если вы считаете, что это было сделано по ошибке, пожалуйста, свяжитесь по почте %s или напишите в телеграм %s.

С уважением,
	Команда отдела аналитики и развития Golden House

Это автоматическое сообщение, пожалуйста, не отвечайте на него.
		`, fullName, username, os.Getenv("SUPPORT_EMAIL"), os.Getenv("SUPPORT_TELEGRAM"))

	return subject, content
}
