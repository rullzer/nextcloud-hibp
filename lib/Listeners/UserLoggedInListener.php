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

namespace OCA\HIBP\Listeners;

use OCA\HIBP\BackgroundJobs\CheckPwnedPassword;
use OCP\BackgroundJob\IJobList;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\Security\ICrypto;
use OCP\User\Events\PostLoginEvent;

class UserLoggedInListener implements IEventListener {

	/** @var IJobList */
	private $jobList;

	/** @var ICrypto */
	private $crypto;

	public function __construct(IJobList $jobList, ICrypto $crypto) {
		$this->jobList = $jobList;
		$this->crypto = $crypto;
	}


	public function handle(Event $event): void {
		if (!($event instanceof PostLoginEvent)) {
			return;
		}

		if ($event->isTokenLogin()) {
			// We don't care about token logins
			return;
		}

		$hash = hash('sha1', $event->getPassword());
		$enc = $this->crypto->encrypt($hash);

		$this->jobList->add(CheckPwnedPassword::class, [
			'uid' => $event->getUser()->getUID(),
			'password' => $enc,
		]);
	}
}
