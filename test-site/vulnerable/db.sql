-- MySQL dump 10.19, Distrib 10.3.38, for debian-linux-gnu
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
);
INSERT INTO `users` VALUES (1,'admin@acme.example','fakehash123');
