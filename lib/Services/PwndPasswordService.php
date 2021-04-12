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

namespace OCA\HIBP\Services;

use OCA\HIBP\AppInfo\Application;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Http\Client\IClientService;
use OCP\Notification\IManager;
use OCP\Security\ICrypto;
use Psr\Log\LoggerInterface;

class PwndPasswordService {
	/** @var ICrypto */
	private $crypto;

	/** @var IClientService */
	private $clientService;

	/** @var LoggerInterface */
	private $logger;

	/** @var IManager */
	private $notificationManager;

	/** @var ITimeFactory */
	private $timeFactory;

	public function __construct(
		ICrypto $crypto,
		IClientService $clientService,
		LoggerInterface $logger,
		IManager $notificationManager,
		ITimeFactory $timeFactory
	) {
		$this->crypto = $crypto;
		$this->clientService = $clientService;
		$this->logger = $logger;
		$this->notificationManager = $notificationManager;
		$this->timeFactory = $timeFactory;
	}

	/**
	 * Actually check the password against the pwned password list
	 */
	public function checkPwnedPassword(string $uid, string $encryptedPassword) {
		$hash = $this->crypto->decrypt($encryptedPassword);

		$range = substr($hash, 0, 5);
		$needle = strtoupper(substr($hash, 5));

		$client = $this->clientService->newClient();

		try {
			$response = $client->get(
				'https://api.pwnedpasswords.com/range/' . $range,
				[
					'timeout' => 5,
					'headers' => [
						'Add-Padding' => 'true'
					]
				]
			);
		} catch (\Exception $e) {
			$this->logger->info('Could not complete pnwed password API request', ['exception' => $e]);
			return;
		}

		$result = $response->getBody();
		$result = preg_replace('/^([0-9A-Z]+:0)$/m', '', $result);

		if (strpos($result, $needle) === false) {
			// Password not found all good
			return;
		}

		$notification = $this->notificationManager->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser($uid)
			->setDateTime($this->timeFactory->getDateTime())
			->setObject('pwndpassword', $range)
			->setSubject('pwndpassword');

		$this->notificationManager->notify($notification);
	}
}
