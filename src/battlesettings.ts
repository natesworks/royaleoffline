import { Logger } from "./logger";
import { base } from "./base";
import { ResourceManager } from "./titan/resourcemanager";
import { PopupBase } from "./titan/flash/gui/popupbase";
import { GameButton } from "./titan/flash/gui/gamebutton";
import { Sprite } from "./titan/flash/sprite";
import { battleSettings, buttonHandlers, userdata } from "./definitions";
import { GUI } from "./titan/flash/gui/gui";
import { DropGUIContainer } from "./titan/flash/gui/dropguicontainer";
import { SCString } from "./titan/utils/scstring";
import { GameSelectableButton } from "./titan/flash/gui/gameselectablebutton";
import { CustomButton } from "./titan/flash/gui/custombutton";
import { GameMode } from "./scroll/client/gamemode";

const isOwnedByAI = new NativeFunction(base.add(0x1ad9ed), "bool", ["pointer"]);

export class BattleSettings {
  open = false;

  settingsButton: GameButton | undefined;
  battleButton: GameButton | undefined;

  popup: PopupBase | null = null;
  closeButton: GameButton | undefined;

  infiniteElixirButton: GameSelectableButton | undefined;

  private gameMode: GameMode | null = null;

  constructor() {
    this.installHooks();
  }

  installHooks() {
    const self: BattleSettings = this;

    Interceptor.attach(base.add(0x121431), {
      onLeave(settingsPopup) {
        battleSettings.createSettingsButton(settingsPopup);
      },
    });

    Interceptor.attach(base.add(0x1226ad), {
      onEnter(args) {
        if (
          battleSettings.settingsButton &&
          args[1].equals(battleSettings.settingsButton.ptr)
        ) {
          battleSettings.createPopup();
          battleSettings.show();
        }
      },
    });

    Interceptor.attach(base.add(0xe9a61), {
      onLeave(combatHUD) {
        self.enterBattle(combatHUD);
      },
    });

    Interceptor.attach(base.add(0x1b39e5), {
      onEnter(args) {
        this.a1 = args[0];
      },
      onLeave(retval) {
        if (userdata.infiniteElixirEnabled && !isOwnedByAI(this.a1))
          retval.replace(ptr(10));
      },
    });

    Interceptor.attach(base.add(0x1b39dd), {
      onEnter(args) {
        this.a1 = args[0];
      },
      onLeave(retval) {
        if (userdata.infiniteElixirEnabled && !isOwnedByAI(this.a1))
          retval.replace(ptr(10));
      },
    });

    Interceptor.attach(base.add(0xa7e35), {
      onEnter(args) {
        self.leaveBattle();
      },
    });
  }

  createPopup() {
    this.popup = new PopupBase("sc/natesworks.sc", "nw_battlesettings");

    this.closeButton = this.popup.addGameButton("close");

    const popupMovieClip = this.popup.getMovieClip();
    const infiniteElixirMovieClip = popupMovieClip.getMovieClipByName(
      "infiniteelixir_button_on",
    );
    this.infiniteElixirButton = new GameSelectableButton();
    this.infiniteElixirButton.setMovieClip(infiniteElixirMovieClip);
    this.infiniteElixirButton.setSelected(userdata.infiniteElixirEnabled);
    this.popup.addChild(this.infiniteElixirButton);

    this.setClickHandler(this.closeButton);
    this.setClickHandler(this.infiniteElixirButton);
  }

  createSettingsButton(settingsPopupPtr: NativePointer) {
    const settingsPopup = new DropGUIContainer(settingsPopupPtr);

    this.settingsButton = settingsPopup.addGameButton("battlesettings_button");
    this.settingsButton.setText(
      "txt",
      SCString.get("TID_BATTLESETTINGS").readContents(),
    );
  }

  enterBattle(combatHUD: NativePointer) {
    this.gameMode = new GameMode(GameMode.getInstance());
    this.createBattleButton(combatHUD);
  }

  leaveBattle() {
    this.gameMode = null;
  }

  createBattleButton(combatHUD: NativePointer) {
    const stageWidth = base.add(0x59ce58).readFloat();
    const stageHeight = base.add(0x59ce5c).readFloat();
    const button = new GameButton();

    let movieclip = ResourceManager.getMovieClip(
      "sc/natesworks.sc",
      "nw_battlesettings_button",
    );
    let movieclip2 = movieclip.getMovieClipByName("battlesettings_button");
    button.setMovieClip(movieclip2);

    button.alpha = 1;
    button.x = stageWidth * 0.5 - button.getWidth() / 2;
    button.y = stageHeight - 1.5 * button.getHeight();
    new Sprite(combatHUD).addChild(button);

    this.battleButton = button;
    this.setClickHandler(this.battleButton);

    Logger.debug("Added nw_battlesettings_button");
  }

  setClickHandler(button: CustomButton | GameButton | GameSelectableButton) {
    const ptr = button.ptr;
    const entry = buttonHandlers.find((e) => e.ptr.equals(ptr));
    const handler = (button: NativePointer) => this.onClick(button);

    if (entry) {
      entry.handler = handler;
    } else {
      buttonHandlers.push({ ptr, handler });
    }
  }

  onClick(button: NativePointer) {
    if (this.battleButton && button.equals(this.battleButton.ptr)) {
      this.createPopup();
      this.show();
    } else if (this.closeButton && button.equals(this.closeButton.ptr)) {
      this.hide();
    } else if (
      this.infiniteElixirButton &&
      button.equals(this.infiniteElixirButton.ptr)
    ) {
      this.toggleInfiniteElixir();
    }
  }

  toggleInfiniteElixir() {
    if (!this.infiniteElixirButton) return; // never true but typescript is a piece of shit

    const newState = !this.infiniteElixirButton.isSelected();
    userdata.infiniteElixirEnabled = newState;
    userdata.write();
    Logger.debug("Infinite elixir set to", userdata.infiniteElixirEnabled);
  }

  show() {
    if (this.popup && !this.popup.ptr.isNull()) {
      GUI.showPopup(this.popup.ptr, 1, 1, 1);
      this.open = true;

      if (this.gameMode) this.gameMode.setPaused(true);
    } else Logger.warn("Attempting to show non-existent popup");
  }

  hide() {
    if (!this.popup || this.popup.ptr.isNull()) {
      Logger.warn("Attempting to hide non-existent popup");
    } else {
      this.popup.modalClose();
      this.open = false;
      this.createPopup();

      if (this.gameMode) this.gameMode.setPaused(true);
    }
  }

  update() {
    if (this.open) {
      if (this.infiniteElixirButton) {
        const state = this.infiniteElixirButton.isSelected();
        const text = state ? "TID_SETTINGS_ON" : "TID_SETTINGS_OFF";
        this.infiniteElixirButton.setText(
          "txt",
          SCString.get(text).readContents(),
        );
      }
    }

    if (this.battleButton) {
    }
  }
}
