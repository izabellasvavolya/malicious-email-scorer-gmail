function onGmailMessage(e) {
  const BACKEND_URL =
    "https://malicious-email-scorer-gmail.onrender.com/analyze";

  const ALERT_THRESHOLD = 30;

  try {
    // Get the currently opened Gmail message
    const accessToken = e.gmail.accessToken;
    const messageId = e.gmail.messageId;

    GmailApp.setCurrentMessageAccessToken(accessToken);

    const message = GmailApp.getMessageById(messageId);

    // --------------------------------------------------
    // ATTACHMENT METADATA
    // --------------------------------------------------

    const attachments = message.getAttachments({
      includeInlineImages: false,
      includeAttachments: true,
    });

    const attachmentMetadata = attachments.map(function (attachment) {
      return {
        name: attachment.getName() || "",
        content_type: attachment.getContentType() || "",
        size: attachment.getSize(),
      };
    });

    // --------------------------------------------------
    // DATA SENT TO FASTAPI
    // --------------------------------------------------

    const payload = {
      sender: message.getFrom(),
      reply_to: message.getReplyTo(),
      authentication_results: message.getHeader("Authentication-Results"),
      subject: message.getSubject(),
      body: message.getPlainBody(),
      attachments: attachmentMetadata,
    };

    // --------------------------------------------------
    // SEND TO BACKEND
    // --------------------------------------------------

    const response = UrlFetchApp.fetch(BACKEND_URL, {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true,
    });

    const statusCode = response.getResponseCode();

    // --------------------------------------------------
    // BACKEND ERROR
    // --------------------------------------------------

    if (statusCode !== 200) {
      return [
        CardService.newCardBuilder()
          .setHeader(
            CardService.newCardHeader()
              .setTitle("Malicious Email Scorer")
              .setSubtitle("Analysis Error"),
          )
          .addSection(
            CardService.newCardSection().addWidget(
              CardService.newTextParagraph().setText(
                "<b>Unable to analyze this email.</b><br>" +
                  "Backend returned status: " +
                  statusCode,
              ),
            ),
          )
          .build(),
      ];
    }

    const result = JSON.parse(response.getContentText());

    const score = Number(result.score);
    const verdict = result.verdict || "Unknown";
    const reasons = result.reasons || [];

    const reasonsText = reasons
      .map(function (reason) {
        return "• " + reason;
      })
      .join("<br><br>");

    const section = CardService.newCardSection();

    // --------------------------------------------------
    // SECURITY ALERT
    // --------------------------------------------------

    if (score > ALERT_THRESHOLD) {
      section.addWidget(
        CardService.newTextParagraph().setText(
          '<font color="#D93025">' +
            "<b>🚨 SECURITY ALERT</b><br><br>" +
            "This email may be dangerous.<br>" +
            "Verify the sender and avoid clicking links " +
            "or sharing sensitive information." +
            "</font>",
        ),
      );

      section.addWidget(CardService.newDivider());
    }

    // --------------------------------------------------
    // RISK SCORE
    // --------------------------------------------------

    let scoreText;

    if (score > ALERT_THRESHOLD) {
      scoreText = '<font color="#D93025"><b>' + score + "/100</b></font>";
    } else {
      scoreText = '<font color="#188038"><b>' + score + "/100</b></font>";
    }

    section.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Risk Score")
        .setText(scoreText),
    );

    // --------------------------------------------------
    // VERDICT
    // --------------------------------------------------

    let verdictText;

    if (score > ALERT_THRESHOLD) {
      verdictText = '<font color="#D93025"><b>' + verdict + "</b></font>";
    } else {
      verdictText = '<font color="#188038"><b>' + verdict + "</b></font>";
    }

    section.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Verdict")
        .setText(verdictText),
    );

    // --------------------------------------------------
    // REASONS
    // --------------------------------------------------

    section.addWidget(CardService.newDivider());

    section.addWidget(
      CardService.newTextParagraph().setText(
        "<b>Why?</b><br><br>" + reasonsText,
      ),
    );

    // --------------------------------------------------
    // RECOMMENDATION
    // --------------------------------------------------

    if (score > ALERT_THRESHOLD) {
      section.addWidget(CardService.newDivider());

      section.addWidget(
        CardService.newTextParagraph().setText(
          "<b>Recommended action</b><br>" +
            "Do not click suspicious links or provide sensitive " +
            "information. Verify the sender through an independent channel.",
        ),
      );
    }

    // --------------------------------------------------
    // BUILD CARD
    // --------------------------------------------------

    const card = CardService.newCardBuilder()
      .setHeader(
        CardService.newCardHeader()
          .setTitle("Malicious Email Scorer")
          .setSubtitle("Email Security Analysis"),
      )
      .addSection(section)
      .build();

    return [card];
  } catch (error) {
    return [
      CardService.newCardBuilder()
        .setHeader(
          CardService.newCardHeader()
            .setTitle("Malicious Email Scorer")
            .setSubtitle("Analysis Error"),
        )
        .addSection(
          CardService.newCardSection().addWidget(
            CardService.newTextParagraph().setText(
              "<b>Something went wrong while analyzing this email.</b><br><br>" +
                error.message,
            ),
          ),
        )
        .build(),
    ];
  }
}
