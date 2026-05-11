package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

const credentialsFile = ".max_credits"

func saveToken(token string) error {
	return os.WriteFile(credentialsFile, []byte(token), 0600)
}

func loadToken() (string, error) {
	data, err := os.ReadFile(credentialsFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// TODO: тупа писать в файл .max_credits ничо не возвращать
func auth(client *Client) string {
	var phone string
	var code string
	var password string
	var token string

	deviceId := uuid.New().String()
	// OPCODE 6 - hello packet
	// вы можете при авторизации изменить OsVersion и DeviceName
	//  чтобы показывало, что вы, например, авторизовались с GoidaOS на MaxPhone или смартфон vivo

	_, err := client.SendSessionInit(
		&SessionInitPayload{
			UserAgent: UserAgent{
				DeviceType:   StringEnum_DESKTOP,
				Locale:       "ru_RU",
				OsVersion:    "Windows",
				DeviceName:   "Smartphone VIVO",
				DeviceLocale: "ru-RU",
				AppVersion:   client.AppVersion,
				Screen:       "956x1470 2.0x",
				Timezone:     "Europe/Moscow",
				BuildNumber:  client.BuildNumber,
			},
			DeviceId:        deviceId,
			ClientSessionId: nil,
		},
	)
	if err != nil {
		panic(err)
	}
	// TODO: нет валидации телефона (должен начинаться с +7...)
	fmt.Print("Phone: ")
	fmt.Scanln(&phone)
	locale := "ru"
	// 2. code auth OPCODE=17
	r1, err := client.SendAuthOneMeAuthRequest(
		&AuthOneMeAuthRequestParameters{
			Phone:    phone,
			Language: &locale,
			Type:     StringEnum_START_AUTH,
		},
	)
	if err != nil {
		panic(err)
	}
	token = r1.Token
	fmt.Print("Code: ")
	// TODO: нет валидации на integer
	fmt.Scanln(&code)
	// 3. send code. OPCODE=18
	r2, err := client.SendAuthOneMeAuth(
		&AuthOneMeAuthParameters{
			Token:         token,
			VerifyCode:    code,
			AuthTokenType: StringEnum_CHECK_CODE,
		},
	)
	if err != nil {
		panic(err)
	}
	// 2FA PASSWORD
	challenge, ok := r2.GetPasswordChallenge()
	if ok {
		// TODO: игнорирует пробельные символы, для демки не дорабатывал этот кейс
		fmt.Print("Password: ")
		fmt.Scanln(&password)
		challengeTrackId, _ := challenge.GetTrackId()
		// OPCODE=115
		r3, err := client.SendAuthOneMeLoginCheckPassword(
			&AuthOneMeLoginCheckPasswordParameters{
				Password: password,
				TrackId:  challengeTrackId,
			},
		)
		if err != nil {
			panic(err)
		}
		// круто, пароль подошел, теперь пихаем его далее в очередной пакет
		// или оно отъебнет, мне было лень ставить loop проверки для демки
		token = r3.TokenAttrs[StringEnum_LOGIN].Token

		if err := saveToken(token); err != nil {
			fmt.Fprintf(os.Stderr, "Warn: cannot save token %s: %v\n", credentialsFile, err)
		} else {
			fmt.Printf("Save auth token")
		}
		return token
	}
	// НЕ ПОКРЫТ СЛУЧАЙ ЕСЛИ ПАРОЛЬ НЕ ЗАПРОСИЛ И ВЕРНУЛ СРАЗУ ТОКЕН
	// РЕАЛЬНО, ВАС НЕ ЗАСТАВИЛИ ПАРОЛЬ ПРИБИВАТЬ, ПРОСТО ТАК ТОКЕН ОТДАЛИ?
	// НАВЕРНОГО ОНО БУДЕТ РАБОТАТЬ, НО ЭТО НЕ ТОЧНО
	// МЕНЯ ЗАСТАВИЛИ НА ТЕСТАХ ПРИБИВАТЬ ПАРОЛЬ
	// ЕСЛИ ЭТОТ КЕЙС НЕПРАВИЛЬНО РАБОТАЕТ, ПРИСЫЛАЙТЕ ПАТЧ
	rTok, ok := r2.GetTokenAttrs()
	if ok {
		// TokenAttrs
		token = rTok[StringEnum_LOGIN].Token
		// OPCODE=19 ПРОШЛИ АВТОРИЗАЦИЮ
		rAuth1, err := client.SendAuthLogin(
			&AuthLoginParameters{
				Token:        token,
				Interactive:  true,
				ChatsSync:    0,
				ContactsSync: 0,
				PresenceSync: -1,
				DraftsSync:   0,
				CallsSync:    0,
				LastLogin:    0,
			},
		)
		if err != nil {
			panic(err)
		}
		finalToken := *rAuth1.Token
		if err := saveToken(finalToken); err != nil {
			fmt.Fprintf(os.Stderr, "Warn: не удалось сохранить токен в %s: %v\n", credentialsFile, err)
		} else {
			fmt.Printf("Токен сохранён в %s\n", credentialsFile)
		}
		return finalToken
	}
	panic(fmt.Errorf("Не удалось получить токен. Попробуйте установить 2FA пароль"))
}

func main() {
	client := NewClient()
	client.VerboseLog = true

	if err := client.Connect(); err != nil {
		panic(err)
	}
	defer client.Close()
	if len(os.Args) > 1 && os.Args[1] == "auth" {
		auth(client)
		return
	}
	// 1. original client ping this service every 30 seconds
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			go client.SendPingPayload(&PingPayload{Interactive: false})
		}
	}()

	// 1. hello packet
	deviceId := uuid.New().String()
	_, err := client.SendSessionInit(
		&SessionInitPayload{
			UserAgent: UserAgent{
				DeviceType:   StringEnum_DESKTOP,
				Locale:       "ru_RU",
				OsVersion:    "Windows",
				DeviceName:   "Smartphone VIVO",
				DeviceLocale: "ru-RU",
				AppVersion:   client.AppVersion,
				Screen:       "956x1470 2.0x",
				Timezone:     "Europe/Moscow",
				BuildNumber:  client.BuildNumber,
			},
			DeviceId:        deviceId,
			ClientSessionId: nil,
		},
	)
	if err != nil {
		panic(err)
	}
	// read token from .max_credits
	token, err := loadToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Токен не найден в %s, запусти с флагом auth: %v\n", credentialsFile, err)
		os.Exit(1)
	}
	var bSync int64 = 0
	// OP=19
	r, err := client.SendAuthLogin(
		&AuthLoginParameters{
			Token:        token,
			ChatsSync:    0,
			ContactsSync: 0,
			PresenceSync: -1,
			CallsSync:    0,
			DraftsSync:   0,
			BannersSync:  &bSync,
			ConfigHash:   "",
			Interactive:  true,
			LastLogin:    0,
		},
	)
	if err != nil {
		log.Printf("AuthLogin failed: %v", err)
		select {}
	}
	profile, ok := r.GetProfile()
	if !ok {
		log.Printf("AuthLogin response missing profile")
		select {}
	}
	names, ok := profile.Contact.GetNames()
	if !ok {
		log.Printf("AuthLogin response missing contact names")
		select {}
	}

	fmt.Println("Hello,", *names[0].FirstName, *names[0].LastName, names[0].Type)

	// обработка нотификаций в этом примере не работает изза неправильных типов в структуре
	client.OnEventsNotificationMessageData(func(payload *EventsNotificationMessageDataPayload) {
		fmt.Println("Enter to callback")
		if !ok {
			return
		}

		text, ok := payload.Message.GetText()
		if !ok {
			return
		}

		chatId := payload.ChatId
		cId := time.Now().Unix() * -1
		notify := true
		elements := []MessageElement{}
		attaches := []OutgoingBaseAttachmentContainer{}
		var textOut string

		switch text {
		case "!помощь":
			textOut = "USAGE:\n!помощь - вывести это сообщение\n!макспобеда МАКСПОБЕДА\n!макс (пошел нахуй)"
			client.SendMessagingSend(
				&MessagingSendParameters{
					ChatId: &chatId,
					Message: OutgoingMessage{
						Cid:      &cId,
						Text:     &textOut,
						Elements: &elements,
						Attaches: &attaches,
					},
					Notify: &notify,
				},
			)
		case "!макспобеда":
			textOut = "МАКСПОБЕДА!!!\nЗарегался в Мах — сначала было немного непривычно после телеги, но быстро втянулся. Интерфейс удобный, всё работает чётко, а главное - своя, отечественная платформа. Приятно осознавать, что можно не зависеть от иностранных сервисов. Советую попробовать! (Текст не редактировать, информацию в скобках удалить. Оплата по ранее указанными реквизитам в течение 15 минут после публикации)"
			client.SendMessagingSend(
				&MessagingSendParameters{
					ChatId: &chatId,
					Message: OutgoingMessage{
						Cid:      &cId,
						Text:     &textOut,
						Elements: &elements,
						Attaches: &attaches,
					},
					Notify: &notify,
				},
			)
			// текущая фича не работает
			// case "!макс":
			// 	textOut = ""
			// 	// вставить свой photo token
			// 	photoToken := ""
			// 	attaches := []OutgoingBaseAttachmentContainer{
			// 		NewOutgoingBaseAttachmentContainer(&OutgoingPhotoAttachment{
			// 			Type:       StringEnum_PHOTO,
			// 			PhotoToken: &photoToken,
			// 		}),
			// 	}
			// 	client.SendMessagingSend(
			// 		&MessagingSendParameters{
			// 			ChatId: &chatId,
			// 			Message: OutgoingMessage{
			// 				Cid:      &cId,
			// 				Text:     &textOut,
			// 				Elements: &elements,
			// 				Attaches: &attaches,
			// 			},
			// 			Notify: &notify,
			// 		},
			// 	)
		}
	})
	// держим программу бесконечно
	select {}
}
