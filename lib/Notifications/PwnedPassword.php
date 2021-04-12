<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2021 Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\HIBP\Notifications;

use OCA\HIBP\AppInfo\Application;
use OCP\L10N\IFactory;
use OCP\Notification\AlreadyProcessedException;
use OCP\Notification\INotification;
use OCP\Notification\INotifier;

class PwnedPassword implements INotifier {

	/** @var IFactory */
	private $l10nFactory;

	public function __construct(IFactory $l10nFactory) {

		$this->l10nFactory = $l10nFactory;
	}

	public function getID(): string {
		return 'hibp_pwnedpassword';
	}

	public function getName(): string {
		return 'hibp';
	}

	public function prepare(INotification $notification, string $languageCode): INotification {
		if ($notification->getApp() !== Application::APP_ID) {
			throw new \InvalidArgumentException();
		}

		if ($notification->getSubject() !== 'pwndpassword') {
			throw new \InvalidArgumentException();
		}

		// Read the language from the notification
		$l = $this->l10nFactory->get(Application::APP_ID, $languageCode);

		$notification->setParsedSubject($l->t('Your password has appeared in a data breach'));
		$notification->setParsedMessage($l->t('Please update your password as soon as possible'));

		return $notification;
	}

}
